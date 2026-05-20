# Copy Fail MCP

<p align="center">
  <a href="https://github.com/casey/just"><img src="https://img.shields.io/badge/just-ready_to_go-7c5cfc?style=flat-square&logo=just&logoColor=white" alt="Just"></a>
  <a href="https://github.com/astral-sh/ruff"><img src="https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json" alt="Ruff"></a>
  <a href="https://python.org"><img src="https://img.shields.io/badge/Python-3.13+-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python"></a>
  <a href="https://biomejs.dev"><img src="https://img.shields.io/badge/Linted_with-Biome-60a5fa?style=flat-square&logo=biome&logoColor=white" alt="Biome"></a>
  <a href="https://github.com/PrefectHQ/fastmcp"><img src="https://img.shields.io/badge/FastMCP-3.2-7c5cfc?style=flat-square" alt="FastMCP"></a>
</p>


> 📖 **[Installation Guide](INSTALL.md)** — quick start, manual setup, and troubleshooting

**CVE-2026-31431 — The worst Linux vulnerability ever discovered. Now controllable via MCP.**

732 bytes of Python. No compilation. No race condition. No per-distro offsets.
One shot, universal root on every Linux kernel built since 2017.

This tool is an MCP server + web dashboard that tests any reachable Linux
system for the vulnerability. It was built because the original PoC is trivial
to use already — this just adds a UI, network scanning, and fleet tracking.

**WARNING:** This is a real kernel LPE. Only use on systems you own or have
explicit written permission to test. Unauthorized use is a felony in most
jurisdictions.

---

## Why This Is the Worst Vulnerability of the Century

| Property | Copy Fail | Dirty COW (2016) | Dirty Pipe (2022) |
|----------|-----------|-------------------|-------------------|
| **Exploit size** | 732 bytes (Python stdlib) | ~200 lines C | ~100 lines C |
| **Compilation needed** | No — pure Python | Yes — compile C | Yes — compile C |
| **Race condition** | No — deterministic | Yes — race window | No |
| **Per-distro offsets** | None — same script everywhere | None | None |
| **On-disk trace** | No — page cache only, checksums clean | No | No |
| **Container escape** | Yes — shared page cache | Yes | Yes |
| **Kernel versions** | >= 4.14 (2017–present) | >= 2.6.22 (2007–2018) | >= 5.8 (2020–2022) |
| **Devices affected** | Billions (still growing) | Fixed in 2018 | Fixed in 2022 |
| **Will never be patched** | Billions of IoT/embedded/routers | Mostly patched | Mostly patched |
| **Found by** | AI (Xint Code, 1 hour scan) | Human researcher | Human researcher |
| **Discovery cost** | ~$6 in cloud compute | Months of human effort | Months of human effort |

### The Four Things That Make It Unprecedented

**1. It was found by an AI in one hour.**
Theori's Xint Code platform scanned the Linux `crypto/` subsystem with a single
operator prompt. One hour later, it had a universal LPE that had evaded every
human reviewer, static analysis tool, and fuzzer for nine years. The bug existed
since 2017 and required cross-subsystem reasoning (AF_ALG socket provenance +
authencesn scratch-write behaviour) — exactly the kind of connection that LLM-
native tools excel at. The discovery cost was negligible. The implications for
the vulnerability landscape are existential.

**2. The exploit is 732 bytes of pure Python, no dependencies.**
No compilation toolchain needed. No libraries to install. No architecture-specific
offsets. It works identically on x86_64 servers, aarch64 routers, ARM NAS devices,
and any other Linux hardware running Python 3.10+. You can paste it into a web
shell, pipe it over netcat, or write it from a USB stick. The barrier to weaponization
is effectively zero.

**3. It leaves no trace on disk.**
The exploit corrupts only the kernel's in-memory page cache. The on-disk binary of
`/usr/bin/su` is never modified. Every file integrity tool that works by comparing
on-disk checksums — AIDE, Tripwire, dm-verity — sees nothing wrong. The corruption
disappears on reboot. The only way to detect that an exploit *was* run is to catch
it in flight via auditd or eBPF. For forensic purposes, the exploit is invisible.

**4. Billions of devices will never be patched.**
The major distros (Ubuntu, RHEL, Debian, SUSE) shipped patches within 72 hours.
But the kernel bug is baked into every Linux device built since 2017 that has
`CONFIG_CRYPTO_USER_API_AEAD=y` — which is essentially all of them. OpenWrt routers
(no patch as of 2026-05-02). IP cameras running vendor kernels from 2019. Smart TVs
with frozen firmware branches. Medical infusion pumps that require FDA re-certification
for every update. Industrial controllers with 10-year support lifecycles. Android
devices are protected by an *accidental* SELinux policy restriction — not a kernel
fix — and rooted/custom-ROM devices, old Fire tablets, and Android TV sticks are
fully exposed. The aggregate number is not millions. It is billions. And for most
of them, the patch is never coming.

---

## What This Tool Does

This is a **security testing and awareness tool** wrapped around the public PoC.
It does nothing that the original 732-byte script doesn't already do. What it adds:

- **Network scanning** — probe a /24 subnet for SSH hosts, identify Linux by banner
- **Fleet overview** — persistent dashboard of discovered hosts with vulnerability status
- **One-click testing** — check kernel, run exploit, apply mitigation from a web UI
- **Safe defaults** — dry-run mitigation, cleanup after exploit, warning banners everywhere
- **Multiple ingress paths** — SSH agent, netcat piping, web shell, physical access

The exploit itself is public, trivially copyable, and cannot be unfound. This tool
exists to make testing fast and safe for people who have authorization to test.

---

## Quick Start

```powershell
git clone https://github.com/sandraschi/copy-fail-mcp
cd copy-fail-mcp
just
```

This opens an interactive dashboard showing all available commands. Run `just bootstrap` to install dependencies, then `just serve` or `just dev` to start.

### Manual Setup

If you don't have `just` installed:
# Install
pip install copy-fail-mcp
# Check a target
copy-fail check --host 192.168.1.100
# Start web dashboard
copy-fail serve --http --port 10955
# Then open http://localhost:10954

## All MCP Tools

| Tool | Description | Ingress |
|------|-------------|---------|
| `cf_scan_network` | Probe /24 subnet for SSH hosts, identify Linux | Direct (async TCP) |
| `cf_check_target` | Check kernel, AEAD config, distro patch status | SSH agent |
| `cf_run_exploit` | Deploy PoC via SSH, execute, report root | SSH agent |
| `cf_assess` | Check + exploit in one step | SSH agent |
| `cf_apply_mitigation` | Module blacklist or initcall blacklist | SSH agent |
| `cf_get_exploit_script` | Return raw 732-byte PoC as text | Any channel |
| `cf_exploit_local` | Write PoC to local path for manual deployment | Local shell |

---

## How the Exploit Works (in 30 seconds)

```
User → AF_ALG socket (authencesn) → splice() target file → HMAC fails
                                                                  ↓
                                     4 bytes written past AEAD boundary
                                               ↓
                                      Into page cache of /usr/bin/su
                                               ↓
                                      su is now corrupted in memory
                                               ↓
                                      Run su → root shell
```

The bug: two subsystem behaviors that were harmless individually become lethal
when combined. AF_ALG's splice path exposes page cache pages as writable output.
authencesn writes 4 bytes past the legitimate AEAD boundary as scratch space.
Put them together and you can corrupt any readable file's in-memory representation
with precisely controlled data. The exploit targets /usr/bin/su's permission check.

---

## License

MIT. The exploit script is by Taeyang Lee / Theori / Xint Code Research Team
([original PoC](https://github.com/theori-io/copy-fail-CVE-2026-31431)).
