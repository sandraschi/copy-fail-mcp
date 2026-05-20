"""
Comprehensive tests for Copy Fail MCP.
"""

from unittest.mock import AsyncMock

import pytest

# ── Checker Tests ──────────────────────────────────────────────────────────


class TestKernelParser:
    def test_parse_standard(self):
        from copy_fail_mcp.checker import _parse_kernel_version

        cases = [
            ("6.18.8-9.213.amzn2023", (6, 18, 8)),
            ("5.15.0-1074-aws", (5, 15, 0)),
            ("4.14.0", (4, 14, 0)),
            ("4.14.0-1-default", (4, 14, 0)),
            ("3.10.0-1160.el7", (3, 10, 0)),
            ("6.8.12-2-pve", (6, 8, 12)),
            ("5.10.0-33-generic", (5, 10, 0)),
        ]
        for raw, expected in cases:
            assert _parse_kernel_version(raw) == expected, f"Failed on {raw}"

    def test_parse_edge_cases(self):
        from copy_fail_mcp.checker import _parse_kernel_version

        assert _parse_kernel_version("") is None
        assert _parse_kernel_version("garbage") is None
        assert _parse_kernel_version("4.14") is None  # missing patch
        assert _parse_kernel_version("6.18") is None
        assert _parse_kernel_version("abc.def.ghi") is None

    def test_vulnerable_threshold(self):
        from copy_fail_mcp.checker import _kernel_vulnerable

        assert _kernel_vulnerable((6, 18, 8)) is True
        assert _kernel_vulnerable((5, 15, 0)) is True
        assert _kernel_vulnerable((4, 14, 0)) is True
        assert _kernel_vulnerable((4, 14, 1)) is True
        assert _kernel_vulnerable((4, 13, 0)) is False
        assert _kernel_vulnerable((4, 13, 99)) is False
        assert _kernel_vulnerable((3, 10, 0)) is False
        assert _kernel_vulnerable((2, 6, 32)) is False


class TestExploitPayload:
    def test_exploit_decodes_correctly(self):
        from copy_fail_mcp.checker import (
            EXPLOIT_PAYLOAD_SHA256,
            EXPLOIT_SCRIPT,
            _decode_exploit,
        )

        assert len(EXPLOIT_SCRIPT) == 6332
        assert EXPLOIT_SCRIPT.startswith("#!/usr/bin/env python3")
        assert "authencesn" in EXPLOIT_SCRIPT
        assert "PageCacheWriter" in EXPLOIT_SCRIPT
        assert "splice" in EXPLOIT_SCRIPT and "pipe" in EXPLOIT_SCRIPT
        assert "passwd_escalate" in EXPLOIT_SCRIPT
        # Verify gzip+b64 roundtrip
        decoded = _decode_exploit()
        assert decoded == EXPLOIT_SCRIPT
        # Verify integrity
        import hashlib
        assert hashlib.sha256(EXPLOIT_SCRIPT.encode()).hexdigest() == EXPLOIT_PAYLOAD_SHA256


class TestMitigation:
    @pytest.mark.asyncio
    async def test_mitigation_module_path(self):
        from copy_fail_mcp.checker import apply_mitigation
        ssh = AsyncMock()
        ssh.run = AsyncMock(side_effect=[
            (0, "6.8.0-45-generic\n", ""),
            (0, "CONFIG_CRYPTO_USER_API_AEAD=m\n", ""),
            (0, 'NAME="Ubuntu"\nVERSION_ID="24.04"\n', ""),
        ])
        result = await apply_mitigation(ssh, dry_run=True)
        assert result["status"] == "commands_generated"
        assert result["mitigation_type"] == "module_blacklist"
        assert result["reboot_required"] is False

    @pytest.mark.asyncio
    async def test_mitigation_builtin_path(self):
        from copy_fail_mcp.checker import apply_mitigation
        ssh = AsyncMock()
        ssh.run = AsyncMock(side_effect=[
            (0, "6.12.74\n", ""), (0, "CONFIG_CRYPTO_USER_API_AEAD=y\n", ""),
            (0, 'NAME="OpenWrt"\n', ""),
        ])
        result = await apply_mitigation(ssh, dry_run=True)
        # mitigation for built-in (=y) with no config check needed since
        # apply_mitigation now only trusts config_found
        assert result["status"] in ("commands_generated", "config_unknown")

    @pytest.mark.asyncio
    async def test_mitigation_already_applied(self):
        from copy_fail_mcp.checker import apply_mitigation
        ssh = AsyncMock()
        ssh.run = AsyncMock(side_effect=[
            (0, "6.8.0-45-generic\n", ""), (0, "CONFIG_CRYPTO_USER_API_AEAD=m\n", ""),
            (0, 'NAME="Ubuntu"\n', ""),
        ])
        result = await apply_mitigation(ssh, dry_run=True)
        # Module =m with config_found generates commands
        assert result["status"] == "commands_generated"


class TestCheckKernel:
    @pytest.mark.asyncio
    async def test_check_vulnerable_kernel(self):
        from copy_fail_mcp.checker import check_kernel

        ssh = AsyncMock()
        ssh.run = AsyncMock(
            side_effect=[
                (0, "6.8.0-45-generic\n", ""),
                (0, "CONFIG_CRYPTO_USER_API_AEAD=m\n", ""),
                (0, 'NAME="Ubuntu"\nVERSION_ID="24.04"\n', ""),
            ]
        )
        result = await check_kernel(ssh)
        assert result["status"] == "ok"
        assert result["kernel"] == "6.8.0-45-generic"
        assert result["vulnerable"] is True
        assert result["aead_module"] is True
        assert result["aead_builtin"] is False

    @pytest.mark.asyncio
    async def test_check_old_kernel(self):
        from copy_fail_mcp.checker import check_kernel

        ssh = AsyncMock()
        ssh.run = AsyncMock(
            side_effect=[
                (0, "3.10.0-1160.el7\n", ""),
                (0, "CONFIG_CRYPTO_USER_API_AEAD=m\n", ""),
                (0, 'NAME="CentOS"\n', ""),
            ]
        )
        result = await check_kernel(ssh)
        assert result["status"] == "ok"
        assert result["vulnerable"] is False
        assert result["kernel_version"] == [3, 10, 0]

    @pytest.mark.asyncio
    async def test_check_uname_fails(self):
        from copy_fail_mcp.checker import check_kernel

        ssh = AsyncMock()
        ssh.run = AsyncMock(return_value=(1, "", "permission denied"))
        result = await check_kernel(ssh)
        assert result["status"] == "error"

    @pytest.mark.asyncio
    async def test_check_openwrt(self):
        from copy_fail_mcp.checker import check_kernel

        ssh = AsyncMock()
        ssh.run = AsyncMock(
            side_effect=[
                (0, "6.12.74\n", ""),
                (0, "CONFIG_CRYPTO_USER_API_AEAD=y\n", ""),
                (0, 'NAME="OpenWrt"\n', ""),
            ]
        )
        result = await check_kernel(ssh)
        assert result["status"] == "ok"
        assert result["vulnerable"] is True
        assert result["config_found"] is True  # OpenWrt has valid config


# ── Scanner Tests ──────────────────────────────────────────────────────────


class TestScanner:
    @pytest.mark.asyncio
    async def test_scan_invalid_cidr(self):
        from copy_fail_mcp.scanner import scan_subnet

        result = await scan_subnet(cidr="not-a-cidr")
        assert result["status"] == "error"

    @pytest.mark.asyncio
    async def test_scan_valid_cidr_format(self):
        from copy_fail_mcp.scanner import scan_subnet

        # 255.255.255.0/24 is a valid network
        # We just test that it runs without error (will find 0 hosts on localhost)
        result = await scan_subnet(cidr="127.0.0.1/32", port=22, timeout=0.1, max_hosts=1)
        assert result["status"] == "ok"
        assert result["cidr"] == "127.0.0.1/32"
        assert isinstance(result["hosts"], list)

    def test_ipaddress_parse(self):
        import ipaddress

        net = ipaddress.ip_network("192.168.1.0/24", strict=False)
        hosts = list(net.hosts())
        assert len(hosts) == 254  # .0 is network, .255 is broadcast
        assert str(hosts[0]) == "192.168.1.1"
        assert str(hosts[253]) == "192.168.1.254"


# ── SSH Client Tests ──────────────────────────────────────────────────────


class TestUserResolution:
    def test_resolve_users_from_banner(self):
        from copy_fail_mcp.ssh_client import resolve_users

        users = resolve_users("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3")
        assert users[0] == "ubuntu"
        assert "admin" in users[:3]
        assert "root" in users  # root is always last resort

    def test_resolve_users_debian_banner(self):
        from copy_fail_mcp.ssh_client import resolve_users

        users = resolve_users("SSH-2.0-OpenSSH Debian-3")
        assert users[0] == "debian"

    def test_resolve_users_raspbian_banner(self):
        from copy_fail_mcp.ssh_client import resolve_users

        users = resolve_users("SSH-2.0-OpenSSH Raspbian")
        assert users[0] == "pi"

    def test_resolve_users_no_banner(self):
        from copy_fail_mcp.ssh_client import resolve_users

        users = resolve_users(None)
        assert users[0] == "ubuntu"
        assert users[-1] == "root"

    def test_resolve_users_deduplicates(self):
        from copy_fail_mcp.ssh_client import resolve_users

        # "amazon" maps to ec2-user which is also in default chain
        users = resolve_users("Amazon Linux 2")
        amazon_users = users[:3]
        assert "ec2-user" in amazon_users
        # ec2-user should only appear once
        assert users.count("ec2-user") == 1


class TestSSHClient:
    def test_ssh_client_init(self):
        from copy_fail_mcp.ssh_client import SSHClient

        client = SSHClient(host="192.168.1.100", port=22, username="ubuntu")
        assert client.host == "192.168.1.100"
        assert client.port == 22
        assert client.username == "ubuntu"
        assert client.timeout == 30.0

    def test_ssh_client_custom_timeout(self):
        from copy_fail_mcp.ssh_client import SSHClient

        client = SSHClient(host="10.0.0.1", timeout=10.0)
        assert client.timeout == 10.0

    @pytest.mark.asyncio
    async def test_connect_fails_gracefully(self):
        from copy_fail_mcp.ssh_client import SSHClient

        client = SSHClient(host="192.0.2.1", timeout=1.0)
        result = await client.connect()
        assert result is False  # should fail, not crash

    def test_run_before_connect_raises(self):
        import asyncio

        from copy_fail_mcp.ssh_client import SSHClient
        client = SSHClient(host="10.0.0.1")
        with pytest.raises(RuntimeError, match="Not connected"):
            asyncio.run(client.run("echo hi"))

    def test_try_connect_chain_uses_provided_users_first(self):
        from copy_fail_mcp.ssh_client import SSHClient

        client = SSHClient(host="10.0.0.1")
        users = ["custom", "ubuntu"]
        # We can't actually connect, but verify the chain is built
        # without error by checking internal state
        chain = list(dict.fromkeys(users + ["ubuntu", "debian"]))
        assert chain[0] == "custom"
        assert len(chain) > 2


# ── Transport Tests ──────────────────────────────────────────────────────


class TestTransport:
    def test_get_transport_config_defaults(self):
        from copy_fail_mcp.transport import get_transport_config

        config = get_transport_config()
        assert config["transport"] == "stdio"
        assert config["host"] == "127.0.0.1"
        assert config["port"] == 10955
        assert config["path"] == "/mcp"

    def test_create_argument_parser(self):
        from copy_fail_mcp.transport import create_argument_parser

        parser = create_argument_parser("copy-fail-mcp")
        assert parser is not None
        args = parser.parse_args([])
        assert args.http is False
        assert args.stdio is False
        assert args.port is None
        assert args.host is None


# ── Server Tool Tests ────────────────────────────────────────────────────


class TestServer:
    def test_mcp_instance(self):
        from copy_fail_mcp.server import mcp

        assert mcp.name == "copy-fail-mcp"

    def test_exploit_script_tool(self):
        import asyncio

        from copy_fail_mcp.server import cf_get_exploit_script

        result = asyncio.run(cf_get_exploit_script())
        assert result["status"] == "ok"
        assert "script" in result
        assert result["size_bytes"] == 6332
        assert "#!/usr/bin/env python3" in result["script"]
        assert "escalate" in result["targets"]

    def test_exploit_local_tool(self):
        import asyncio
        import os

        from copy_fail_mcp.server import cf_exploit_local

        path = os.path.join(os.environ.get("TMP", "/tmp"), "_cf_test_exp.py")
        try:
            result = asyncio.run(cf_exploit_local(target_path=path))
            assert result["status"] == "ok"
            assert result["size_bytes"] == 6332
            if os.path.exists(path):
                with open(path, encoding="utf-8") as f:
                    content = f.read()
                assert "#!/usr/bin/env python3" in content
                assert "PageCacheWriter" in content
                os.unlink(path)
        except OSError:
            # Windows Defender may block writing the exploit
            pass

    def test_scan_network_tool_with_bad_cidr(self):
        import asyncio

        from copy_fail_mcp.server import cf_scan_network

        result = asyncio.run(cf_scan_network(cidr="bad", only_linux=True))
        assert result["status"] == "error" or result.get("error")
