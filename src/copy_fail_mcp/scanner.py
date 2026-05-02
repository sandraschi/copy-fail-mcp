"""
Local network scanner for discovering Linux hosts via SSH port probing.

Uses async TCP connect scans — no dependencies beyond asyncio.
No ICMP, no raw sockets, no special permissions required.
"""

import asyncio
import ipaddress
import logging
import re
import socket

logger = logging.getLogger(__name__)


async def _probe_host(ip: str, port: int = 22, timeout: float = 2.0) -> dict | None:
    """Probe a single host:port. Returns info dict if open, None if closed."""
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout,
        )
        banner = ""
        try:
            # Read SSH banner (first line, usually starts with SSH-2.0-)
            reader, _ = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=timeout,
            )
            banner_bytes = await asyncio.wait_for(reader.readline(), timeout=2.0)
            banner = banner_bytes.decode("utf-8", errors="replace").strip()
        except Exception:
            pass

        is_linux = False
        os_hint = "unknown"

        # Check SSH banner for Linux/Unix indicators
        if banner:
            banner_lower = banner.lower()
            if any(x in banner_lower for x in ["linux", "ubuntu", "debian", "raspbian",
                                                 "openwrt", "alpine", "openssh"]):
                is_linux = True
                os_hint = banner

        return {
            "ip": ip,
            "port": port,
            "open": True,
            "is_linux": is_linux,
            "os_hint": os_hint,
            "banner": banner,
        }
    except (TimeoutError, ConnectionRefusedError, OSError):
        return None


async def _scan_cidr(cidr: str, port: int = 22, timeout: float = 1.5, max_hosts: int = 256) -> list[dict]:
    """Scan a CIDR range (e.g., 192.168.1.0/24) for hosts with open port."""
    network = ipaddress.ip_network(cidr, strict=False)
    sem = asyncio.Semaphore(50)  # concurrency limit

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


async def _scan_ports(host: str, ports: list[int], timeout: float = 1.0) -> list[dict]:
    """Scan specific ports on a single host."""
    sem = asyncio.Semaphore(20)

    async def _probe(p: int) -> dict | None:
        async with sem:
            return await _probe_host(host, port=p, timeout=timeout)

    tasks = [_probe(p) for p in ports]
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
        cidr: CIDR notation (e.g., '192.168.1.0/24', '10.0.0.0/24').
        port: TCP port to probe (default: 22 for SSH).
        timeout: Seconds to wait per host probe.
        max_hosts: Max IPs to scan (prevents huge scans).
        only_linux: If True, only return hosts identified as Linux via SSH banner.

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


__all__ = ["scan_subnet"]
