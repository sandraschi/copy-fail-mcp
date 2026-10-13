# copy-fail-mcp (MCPB Bundle)

CVE-2026-31431 Copy Fail — Linux kernel LPE tester via MCP

## Usage

Add to \claude_desktop_config.json\:
\\\json
{
  "mcpServers": {
    "copy-fail-mcp": {
      "command": "uv",
      "args": ["run", "--directory", "\D:\Dev\repos", "python", "-m", "copy_fail_mcp"],
      "env": { "PYTHONPATH": "\D:\Dev\repos/src" }
    }
  }
}
\\\

## Tools

- **cf_get_exploit_script**: cf_get_exploit_script

## Requirements

- Python 3.12+
- uv
