"""
CLI interface for Copy Fail MCP tester.
"""

import os

import click
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from .server import mcp
from .transport import run_server

console = Console()


@click.group()
def cli():
    """CVE-2026-31431 Copy Fail — Linux kernel LPE tester via MCP"""
    pass


@cli.command()
@click.option("--http", "http_mode", is_flag=True, help="HTTP Streamable mode")
@click.option("--port", type=int, default=None, help="HTTP port (default: 10955)")
@click.option("--host", default=None, help="HTTP bind address")
def serve(http_mode: bool, port: int | None, host: str | None):
    """Start the Copy Fail MCP server"""
    console.print(
        Panel.fit(
            Text("Copy Fail MCP Server", style="bold red"),
            subtitle="CVE-2026-31431 Linux LPE Tester",
            border_style="red",
        )
    )
    console.print()
    console.print("Available tools:", style="cyan")
    console.print("  cf_check_target  - Check kernel vulnerability")
    console.print("  cf_run_exploit   - Run the PoC (requires confirmation)")
    console.print("  cf_assess        - Full check + optional exploit")
    console.print()

    transport = "http" if http_mode else os.getenv("MCP_TRANSPORT", "stdio")
    if transport == "http":
        console.print(f"HTTP mode on http://{host or '127.0.0.1'}:{port or 10955}/mcp", style="yellow")
    else:
        console.print("STDIO mode", style="yellow")

    try:
        run_server(mcp, server_name="copy-fail-mcp", transport=transport, host=host or "127.0.0.1", port=port or 10955)
    except KeyboardInterrupt:
        console.print("\nServer stopped", style="red")
    except Exception as e:
        console.print(f"\nError: {e}", style="red")
        raise click.Abort()


@cli.command()
@click.option("--subnet", default="192.168.1.0/24", help="CIDR subnet to scan")
@click.option("--timeout", default=1.0, help="Seconds per host probe")
@click.option("--all", "show_all", is_flag=True, help="Show all hosts, not just Linux")
def scan(subnet: str, timeout: float, show_all: bool):
    """Scan a local subnet for Linux hosts with SSH open"""
    import asyncio

    from .scanner import scan_subnet

    console.print(f"Scanning {subnet} on port 22...", style="cyan")
    console.print(f"This will probe up to 256 IPs ({timeout}s timeout each)", style="yellow")
    console.print()

    async def _run():
        result = await scan_subnet(
            cidr=subnet,
            port=22,
            timeout=timeout,
            max_hosts=256,
            only_linux=not show_all,
        )
        if result["status"] == "error":
            console.print(f"Error: {result['error']}", style="red")
            return

        hosts = result["hosts"]
        console.print(f"Found {len(hosts)} host(s):", style="green")
        console.print()
        for h in hosts:
            label = "LINUX" if h["is_linux"] else "unknown"
            console.print(f"  {h['ip']:15}  [{label}]  {h.get('banner', '')[:60]}")

    asyncio.run(_run())


@cli.command()
@click.option("--host", required=True, help="Target hostname or IP")
@click.option("--user", default="ubuntu", help="SSH username")
@click.option("--port", default=22, help="SSH port")
@click.option("--auto-user", "auto_user", is_flag=True, help="Auto-detect SSH username via common distro list")
@click.option("--force", is_flag=True, help="Run exploit even if not vulnerable")
def check(host: str, user: str, port: int, auto_user: bool, force: bool):
    """Check a host and optionally run the exploit (one-shot CLI)"""
    label = f"auto@{host}:{port}" if auto_user else f"{user}@{host}:{port}"
    console.print(f"[bold]Target:[/bold] {label}")
    console.print("[yellow]WARNING: This runs a REAL kernel LPE. Ensure you have permission.[/yellow]")

    if force:
        if not click.confirm("Run the exploit on this target?", default=False):
            console.print("Aborted.", style="red")
            return

    import asyncio

    from .checker import assess as run_assess
    from .ssh_client import SSHClient

    async def _run():
        ssh = SSHClient(host=host, port=port, username=user)
        if auto_user:
            ok, connected_user = await ssh.try_connect_chain()
            if not ok:
                console.print("Could not connect with any common username.", style="red")
                return
            console.print(f"Connected as [green]{connected_user}[/green]")
        else:
            if not await ssh.connect():
                console.print("SSH connection failed.", style="red")
                return
        try:
            result = await run_assess(ssh, force=force)
            from rich import print as rprint

            rprint(result)
        finally:
            await ssh.close()

    asyncio.run(_run())


def main():
    cli()


if __name__ == "__main__":
    main()
