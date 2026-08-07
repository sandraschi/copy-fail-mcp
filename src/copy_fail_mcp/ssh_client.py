"""
SSH client module for remote Linux access.

Uses asyncssh with SSH agent forwarding. No passwords stored.
Includes automatic user enumeration via common distro usernames.
"""

import asyncio
import logging

import asyncssh

logger = logging.getLogger(__name__)

# Banner keywords -> preferred usernames for that distro (first = most common)
BANNER_USER_MAP: dict[str, list[str]] = {
    "ubuntu": ["ubuntu", "admin"],
    "debian": ["debian", "admin"],
    "raspbian": ["pi", "admin"],
    "amazon": ["ec2-user", "admin"],
    "alpine": ["alpine", "admin"],
    "openwrt": ["root", "admin"],
    "fedora": ["fedora", "admin"],
    "centos": ["centos", "admin"],
    "rocky": ["rocky", "admin"],
    "arch": ["arch", "admin"],
    "suse": ["suse", "admin"],
    "opensuse": ["suse", "admin"],
}

# Fallback chain when banner doesn't match anything known
DEFAULT_USER_CHAIN: list[str] = [
    "ubuntu",
    "debian",
    "ec2-user",
    "admin",
    "pi",
    "azureuser",
    "fedora",
    "alpine",
    "user",
    "root",
]


def resolve_users(banner_hint: str | None = None) -> list[str]:
    """Return a prioritized list of usernames to try.

    If banner_hint matches a known distro, that distro's users come first,
    followed by the general fallback chain (deduplicated).
    """
    seen: set[str] = set()
    result: list[str] = []

    if banner_hint:
        hint_lower = banner_hint.lower()
        for keyword, users in BANNER_USER_MAP.items():
            if keyword in hint_lower:
                for u in users:
                    if u not in seen:
                        result.append(u)
                        seen.add(u)
                break

    for u in DEFAULT_USER_CHAIN:
        if u not in seen:
            result.append(u)
            seen.add(u)

    return result


class SSHClient:
    """Async SSH connection to a remote Linux host using agent forwarding."""

    def __init__(self, host: str, port: int = 22, username: str = "ubuntu", timeout: float = 30.0):
        self.host = host
        self.port = port
        self.username = username
        self.timeout = timeout
        self._conn: asyncssh.SSHClientConnection | None = None

    async def connect(self, key_path: str | None = None) -> bool:
        """Establish SSH connection with agent forwarding.

        Args:
            key_path: Optional path to an SSH private key for auth.
        """
        kwargs: dict = {
            "host": self.host,
            "port": self.port,
            "username": self.username,
            "agent_forwarding": True,
            "known_hosts": None,
        }
        if key_path:
            kwargs["client_keys"] = [key_path]
        try:
            self._conn = await asyncio.wait_for(
                asyncssh.connect(**kwargs),
                timeout=self.timeout,
            )
            logger.info(f"SSH connected to {self.username}@{self.host}:{self.port}")
            return True
        except TimeoutError:
            logger.error(f"SSH connection timed out to {self.host}:{self.port}")
            return False
        except asyncssh.Error as e:
            logger.error(f"SSH connection failed to {self.host}:{self.port}: {e}")
            return False

    async def connect_as(self, username: str) -> bool:
        """Establish SSH connection with a specific username."""
        self.username = username
        self._conn = None
        return await self.connect()

    async def try_connect_chain(
        self, users: list[str] | None = None, banner_hint: str | None = None
    ) -> tuple[bool, str | None]:
        """Try connecting with each username in priority order.

        Returns (success, username_that_worked).
        First try users list, then resolve from banner hint, then default chain.
        """
        chain: list[str] = users or []
        if banner_hint:
            for u in resolve_users(banner_hint):
                if u not in chain:
                    chain.append(u)
        for u in DEFAULT_USER_CHAIN:
            if u not in chain:
                chain.append(u)

        for user in chain:
            ok = await self.connect_as(user)
            if ok:
                return True, user

        return False, None

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
        except TimeoutError:
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
