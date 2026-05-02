"""
FastMCP Dual Transport Configuration (copy of sdr-mcp standard).
"""

import argparse
import asyncio
import logging
import os

logger = logging.getLogger(__name__)

ENV_TRANSPORT = "MCP_TRANSPORT"
ENV_HOST = "MCP_HOST"
ENV_PORT = "MCP_PORT"
ENV_PATH = "MCP_PATH"
DEFAULT_PORT = 10955
DEFAULT_HOST = "127.0.0.1"


def get_transport_config() -> dict:
    return {
        "transport": os.getenv(ENV_TRANSPORT, "stdio").lower(),
        "host": os.getenv(ENV_HOST, DEFAULT_HOST),
        "port": int(os.getenv(ENV_PORT, str(DEFAULT_PORT))),
        "path": os.getenv(ENV_PATH, "/mcp"),
    }


def create_argument_parser(server_name: str) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=f"{server_name} - MCP Server",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    g = parser.add_mutually_exclusive_group()
    g.add_argument("--stdio", action="store_true", help="STDIO mode (default)")
    g.add_argument("--http", action="store_true", help="HTTP Streamable mode")
    parser.add_argument("--host", default=None, help="Bind address")
    parser.add_argument("--port", type=int, default=None, help="Port")
    parser.add_argument("--path", default=None, help="HTTP endpoint path")
    parser.add_argument("--debug", action="store_true", help="Debug logging")
    return parser


def run_server(
    mcp_app,
    args: argparse.Namespace | None = None,
    server_name: str = "copy-fail-mcp",
    transport: str | None = None,
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    path: str = "/mcp",
) -> None:
    asyncio.run(run_server_async(mcp_app, args, server_name, transport, host, port, path))


async def run_server_async(
    mcp_app,
    args: argparse.Namespace | None = None,
    server_name: str = "copy-fail-mcp",
    transport: str | None = None,
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    path: str = "/mcp",
) -> None:
    if args is None and transport is None:
        parser = create_argument_parser(server_name)
        args = parser.parse_args()
        t = "http" if args.http else ("stdio" if args.stdio else os.getenv(ENV_TRANSPORT, "stdio"))
        h = args.host or host
        p = args.port or port
        pa = args.path or path
    elif args is not None:
        t = "http" if args.http else ("stdio" if args.stdio else os.getenv(ENV_TRANSPORT, "stdio"))
        h = args.host or host
        p = args.port or port
        pa = args.path or path
    else:
        t = transport or os.getenv(ENV_TRANSPORT, "stdio")
        h = host
        p = port
        pa = path

    if args and args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    logger.info(f"Starting {server_name}, transport={t}")

    try:
        if t == "http":
            logger.info(f"HTTP mode: http://{h}:{p}{pa}")
            await mcp_app.run_http_async(host=h, port=p, path=pa)
        else:
            logger.info("STDIO mode")
            await mcp_app.run_stdio_async()
    except asyncio.CancelledError:
        logger.info(f"{server_name} cancelled")
    except Exception as e:
        logger.error(f"{server_name} failed: {e}", exc_info=True)
        raise
