"""
Local network scanner for discovering Linux hosts via SSH port probing.

Uses async TCP connect scans — no dependencies beyond asyncio.
"""

import asyncio
import ipaddress
import logging

logger = logging.getLogger(__name__)


async def _probe_host(ip: str, port: int = 22, timeout: float = 2.0) -> dict | None:
    """Probe a single host:port. Returns info dict if open, None if closed."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout,
        )

        banner = ""
        try:
            banner_bytes = await asyncio.wait_for(reader.readline(), timeout=2.0)
            banner = banner_bytes.decode("utf-8", errors="replace").strip()
        except Exception:
            pass
        finally:
            writer.close()
            await writer.wait_closed()

        is_linux = False
        if banner:
            banner_lower = banner.lower()
            if any(
                x in banner_lower for x in ["linux", "ubuntu", "debian", "raspbian", "openwrt", "alpine", "openssh"]
            ):
                is_linux = True

        return {
            "ip": ip,
            "port": port,
            "open": True,
            "is_linux": is_linux,
            "os_hint": banner or "unknown",
            "banner": banner,
        }

    except (TimeoutError, ConnectionRefusedError, OSError):
        return None


async def _scan_cidr(cidr: str, port: int = 22, timeout: float = 1.5, max_hosts: int = 256) -> list[dict]:
    """Scan a CIDR range for hosts with open port."""
    network = ipaddress.ip_network(cidr, strict=False)
    sem = asyncio.Semaphore(50)

    async def _probe_with_sem(ip: str) -> dict | None:
        async with sem:
            return await _probe_host(ip, port=port, timeout=timeout)

    tasks = []
    count = 0
    for ip in network.hosts():
        if count >= max_hosts:
            break
        tasks.append(_probe_with_sem(str(ip)))
        count += 1

    results = await asyncio.gather(*tasks)
    return [r for r in results if r is not None]


async def scan_subnet(
    cidr: str = "192.168.1.0/24",
    port: int = 22,
    timeout: float = 1.5,
    max_hosts: int = 256,
    only_linux: bool = False,
) -> dict:
    """Scan a subnet for hosts with an open port (default: SSH port 22).

    Args:
        cidr: CIDR notation (e.g., '192.168.1.0/24').
        port: TCP port to probe (default: 22).
        timeout: Seconds to wait per host probe.
        max_hosts: Max IPs to scan.
        only_linux: If True, only return hosts identified as Linux.

    Returns:
        Dict with scan results summary and host list.
    """
    logger.info(f"Scanning {cidr} on port {port} (timeout={timeout}s, max={max_hosts})")

    try:
        hosts = await _scan_cidr(cidr, port=port, timeout=timeout, max_hosts=max_hosts)
    except ValueError as e:
        return {"status": "error", "error": f"Invalid CIDR: {e}"}

    if only_linux:
        hosts = [h for h in hosts if h.get("is_linux")]

    return {
        "status": "ok",
        "cidr": cidr,
        "port": port,
        "total_hosts_found": len(hosts),
        "linux_hosts": len([h for h in hosts if h.get("is_linux")]),
        "hosts": sorted(hosts, key=lambda h: h["is_linux"], reverse=True),
    }
