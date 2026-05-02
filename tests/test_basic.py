"""
Basic tests for Copy Fail MCP.
"""

import pytest
from unittest.mock import patch, MagicMock


class TestChecker:
    """Test the kernel version parser."""

    def test_parse_kernel_version(self):
        from copy_fail_mcp.checker import _parse_kernel_version, _kernel_vulnerable

        assert _parse_kernel_version("6.18.8-9.213.amzn2023") == (6, 18, 8)
        assert _parse_kernel_version("5.15.0-1074-aws") == (5, 15, 0)
        assert _parse_kernel_version("4.14.0") == (4, 14, 0)
        assert _parse_kernel_version("3.10.0-1160") == (3, 10, 0)
        assert _parse_kernel_version("garbage") is None

    def test_kernel_vulnerable(self):
        from copy_fail_mcp.checker import _kernel_vulnerable

        assert _kernel_vulnerable((6, 18, 8)) is True
        assert _kernel_vulnerable((4, 14, 0)) is True
        assert _kernel_vulnerable((5, 10, 0)) is True
        assert _kernel_vulnerable((3, 10, 0)) is False
        assert _kernel_vulnerable((4, 13, 0)) is False
