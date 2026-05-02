# Copy Fail MCP

**CVE-2026-31431 Linux kernel LPE tester via MCP (Model Context Protocol).**

Test any Linux system for the Copy Fail vulnerability by SSHing in,
checking kernel version, and optionally running the 732-byte Python PoC.

**WARNING:** This is a REAL kernel privilege escalation exploit. Only use
on systems you own or have explicit written permission to test.

---

## Quick Start

```bash
# Install
pip install copy-fail-mcp

# Check a target
copy-fail check --host 192.168.1.100

# Start MCP server (STDIO mode)
copy-fail serve
```

## Tools

| Tool | Description |
|------|-------------|
| `cf_check_target` | Check kernel version, AEAD config, distro patch status |
| `cf_run_exploit` | Deploy and execute the PoC on a vulnerable target |
| `cf_assess` | Full check + conditional exploit |

## Safety

Every tool returns a prominent warning banner. The exploit is only executed
if the kernel is confirmed vulnerable AND no distro patch is available.

## How It Works

```
User → MCP client → copy-fail-mcp → SSH (agent) → target Linux
                                                      ↓
                                             uname -r check
                                             config check
                                             deploy PoC (if vulnerable)
                                             run exploit
                                             report result
```

The PoC uses AF_ALG AEAD socket + splice to write 4 controlled bytes into
the page cache of `/usr/bin/su`, corrupting it in memory (not on disk) to
escalate to root. Requires Python 3.10+ on the target, nothing else.

## License

MIT. The bundled exploit is from Theori / Xint Code Research Team
([original PoC](https://github.com/theori-io/copy-fail-CVE-2026-31431)).
