"""Diagnose file write encoding issue."""
import os, asyncio
from copy_fail_mcp.server import cf_exploit_local

path = os.path.join(os.environ.get("TMP", "/tmp"), "_cf_test_diag.py")
result = asyncio.run(cf_exploit_local(target_path=path))
print("Write result:", result["status"])

with open(path, "rb") as f:
    raw = f.read()
print(f"File on disk: {len(raw)} bytes")

if len(raw) > 5444:
    print(f"Byte at 5444: {raw[5444]:#x}")
else:
    print(f"File is only {len(raw)} bytes")

try:
    content = raw.decode("utf-8")
    print("UTF-8 decode: OK,", len(content), "chars")
except UnicodeDecodeError as e:
    print("UTF-8 decode FAILED:", e)
    for i in range(len(raw)):
        try:
            raw[i : i + 1].decode("utf-8")
        except Exception:
            print(f"  First bad byte at pos {i}: {raw[i]:#x}")
            ctx = raw[max(0, i - 10) : i + 10]
            print(f"  Context hex: {ctx.hex()}")
            break

os.unlink(path)
