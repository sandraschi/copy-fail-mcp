"""
SSH client module for remote Linux access.

Uses asyncssh with SSH agent forwarding. No passwords stored.
"""

import asyncio
import logging
from typing import Optional

import asyncssh

logger = logging.getLogger(__name__)


class SSHClient:
    """Async SSH connection to a remote Linux host using agent forwarding."""

    def __init__(self, host: str, port: int = 22, username: str = "root", timeout: float = 30.0):
        self.host = host
        self.port = port
        self.username = username
        self.timeout = timeout
        self._conn: Optional[asyncssh.SSHClientConnection] = None

    async def connect(self) -> bool:
        """Establish SSH connection with agent forwarding."""
        try:
            self._conn = await asyncio.wait_for(
                asyncssh.connect(
                    self.host,
                    port=self.port,
                    username=self.username,
                    agent_forwarding=True,
                    known_hosts=None,
                ),
                timeout=self.timeout,
            )
            logger.info(f"SSH connected to {self.username}@{self.host}:{self.port}")
            return True
        except asyncio.TimeoutError:
            logger.error(f"SSH connection timed out to {self.host}:{self.port}")
            return False
        except asyncssh.Error as e:
            logger.error(f"SSH connection failed to {self.host}:{self.port}: {e}")
            return False

    async def run(self, command: str, timeout: float = 60.0) -> tuple[int, str, str]:
        """Run a command via SSH and return (exit_code, stdout, stderr)."""
        if not self._conn:
            raise RuntimeError("Not connected. Call connect() first.")

        try:
            result = await asyncio.wait_for(
                self._conn.run(command),
                timeout=timeout,
            )
            return (result.returncode or 0, result.stdout or "", result.stderr or "")
        except asyncio.TimeoutError:
            logger.warning(f"Command timed out on {self.host}: {command[:80]}")
            return (-1, "", "TIMEOUT")
        except asyncssh.Error as e:
            logger.error(f"SSH command failed: {e}")
            return (-1, "", str(e))

    async def write_file(self, remote_path: str, content: str) -> bool:
        """Write a string to a remote file via SFTP."""
        if not self._conn:
            raise RuntimeError("Not connected.")

        try:
            async with self._conn.start_sftp_client() as sftp:
                async with sftp.open(remote_path, "w") as f:
                    await f.write(content)
            logger.info(f"Wrote {len(content)} bytes to {remote_path}")
            return True
        except Exception as e:
            logger.error(f"SFTP write failed: {e}")
            return False

    async def close(self):
        """Close the SSH connection."""
        if self._conn:
            self._conn.close()
            self._conn = None
            logger.info("SSH connection closed")
