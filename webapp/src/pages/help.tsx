import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { AlertTriangle, Shield, Terminal, BookOpen, Globe, Wifi, Network, Smartphone, UserCheck, Bug, Skull, FlaskConical } from "lucide-react";

const safety_warnings = [
  {
    title: "This is a REAL Exploit",
    body: "CVE-2026-31431 Copy Fail is a confirmed Linux kernel local privilege escalation. The PoC corrupts /usr/bin/su in memory to gain root. Only run on systems you own or have explicit written permission to test.",
    severity: "critical",
  },
  {
    title: "No On-Disk Changes",
    body: "The exploit writes only to the page cache — the on-disk binary is NOT modified. A reboot clears the corruption. However, the running process gains full root access.",
    severity: "info",
  },
  {
    title: "SSH Agent Forwarding",
    body: "Default mode uses SSH agent. No passwords stored or transmitted. Your key must be loaded (ssh-add -l) and the target must accept it.",
    severity: "info",
  },
  {
    title: "IoT Devices (Tapo, Smart Plugs, Cameras)",
    body: "Many IoT devices run vulnerable kernels but lack SSH access without jailbreaking. Do NOT test devices you do not own. The network scanner only finds port 22 hosts.",
    severity: "critical",
  },
  {
    title: "Legal Warning",
    body: "Unauthorized access to computer systems is illegal under CFAA and equivalent laws worldwide. This tool provides no anonymity or protection.",
    severity: "critical",
  },
];

export function Help() {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold tracking-tight text-white">Help & Safety</h2>
          <p className="text-slate-400">Multi-level guide: beginner to advanced</p>
        </div>
      </div>

      <Card className="border-red-500 bg-red-950/20">
        <CardContent className="p-4 flex items-start gap-3">
          <AlertTriangle className="h-5 w-5 text-red-500 mt-0.5 shrink-0" />
          <div>
            <p className="text-sm font-bold text-red-400 mb-1">CRITICAL: Read Before Using</p>
            <p className="text-xs text-red-300/80">
              This tool deploys and executes a real kernel LPE. Designed for authorized
              security testing only. The maintainers assume no liability for misuse.
            </p>
          </div>
        </CardContent>
      </Card>

      <Tabs defaultValue="beginner" className="w-full">
        <TabsList className="w-full">
          <TabsTrigger value="beginner" className="flex-1">
            <BookOpen className="h-3.5 w-3.5 mr-1.5" /> Beginner
          </TabsTrigger>
          <TabsTrigger value="intermediate" className="flex-1">
            <Terminal className="h-3.5 w-3.5 mr-1.5" /> Intermediate
          </TabsTrigger>
          <TabsTrigger value="advanced" className="flex-1">
            <Bug className="h-3.5 w-3.5 mr-1.5" /> Advanced
          </TabsTrigger>
          <TabsTrigger value="safety" className="flex-1">
            <Shield className="h-3.5 w-3.5 mr-1.5" /> Safety
          </TabsTrigger>
        </TabsList>

        {/* BEGINNER */}
        <TabsContent value="beginner" className="space-y-3">
          <Card className="border-slate-800 bg-slate-950/50">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <UserCheck className="h-4 w-4 text-emerald-400" /> What is this tool?
              </CardTitle>
            </CardHeader>
            <CardContent className="text-xs text-slate-400 space-y-2">
              <p>It tests Linux computers for a specific security vulnerability called
              <strong className="text-red-400"> CVE-2026-31431 "Copy Fail"</strong>. If the target
              is vulnerable, the tool can prove it by temporarily gaining full control (root).</p>
              <p>The vulnerability affects nearly every Linux computer made since 2017. Most
              major distributions (Ubuntu, RHEL, Debian) have released fixes. Many devices
              (routers, cameras, smart TVs) will <strong className="text-yellow-400">never</strong> be fixed.</p>
            </CardContent>
          </Card>

          <Card className="border-slate-800 bg-slate-950/50">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Wifi className="h-4 w-4 text-cyan-400" /> Can we do this at a coffee shop?
              </CardTitle>
            </CardHeader>
            <CardContent className="text-xs text-slate-400 space-y-2">
              <p><strong className="text-red-400">No.</strong> Coffee shop / public WiFi uses
              <strong className="text-yellow-400">client isolation</strong> — your laptop cannot
              talk directly to any other laptop on the same WiFi, even though you're on the
              same network. This is a security feature of the WiFi access point.</p>
              <p className="bg-slate-900/50 p-2 rounded border border-slate-700">
                <strong className="text-emerald-400">Demo fix:</strong> Use a phone hotspot instead.
                Both laptops connect to the same phone. Hotspots do NOT use client isolation.
                Works every time.
              </p>
            </CardContent>
          </Card>

          <Card className="border-slate-800 bg-slate-950/50">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Network className="h-4 w-4 text-cyan-400" /> What do I need for a demo?
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-2 text-xs text-slate-400">
                <div className="flex items-start gap-2">
                  <FlaskConical className="h-3.5 w-3.5 mt-0.5 text-slate-500 shrink-0" />
                  <div><strong className="text-slate-300">Two laptops</strong> — yours (attacker) and a friend's (target, running Ubuntu 22.04+ that has NOT run apt upgrade since May 1)</div>
                </div>
                <div className="flex items-start gap-2">
                  <FlaskConical className="h-3.5 w-3.5 mt-0.5 text-slate-500 shrink-0" />
                  <div><strong className="text-slate-300">Phone hotspot</strong> — both laptops connect to it (NOT the coffee shop WiFi)</div>
                </div>
                <div className="flex items-start gap-2">
                  <FlaskConical className="h-3.5 w-3.5 mt-0.5 text-slate-500 shrink-0" />
                  <div><strong className="text-slate-300">SSH access</strong> — friend's laptop must have openssh-server running and your SSH key added</div>
                </div>
                <div className="flex items-start gap-2">
                  <FlaskConical className="h-3.5 w-3.5 mt-0.5 text-slate-500 shrink-0" />
                  <div><strong className="text-slate-300">Copy Fail MCP</strong> — this tool running on your laptop, either STDIO mode or webapp</div>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card className="border-slate-800 bg-slate-950/50">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Terminal className="h-4 w-4 text-cyan-400" /> Step-by-step demo
              </CardTitle>
            </CardHeader>
            <CardContent>
              <ol className="space-y-2 text-xs text-slate-400 list-decimal list-inside">
                <li>Both laptops: connect to the <strong className="text-emerald-400">same phone hotspot</strong></li>
                <li>Friend's laptop: <code className="text-cyan-400 font-mono">ip addr</code> to find their IP (e.g., 192.168.43.50)</li>
                <li>Your laptop: <code className="text-cyan-400 font-mono">nc -zv 192.168.43.50 22</code> — should say "Connected"</li>
                <li>Your laptop: open this webapp, enter the friend's IP in the <strong>Test Target</strong> tab</li>
                <li>Click <strong>Check Only</strong> first — shows kernel version and vulnerability status</li>
                <li>If it says "Vulnerable: YES", click <strong>Full Assessment</strong> — runs the exploit</li>
                <li>Watch for "ROOT OBTAINED" — the demo is complete</li>
              </ol>
            </CardContent>
          </Card>
        </TabsContent>

        {/* INTERMEDIATE */}
        <TabsContent value="intermediate" className="space-y-3">
          <Card className="border-slate-800 bg-slate-950/50">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Terminal className="h-4 w-4 text-cyan-400" /> All MCP Tools
              </CardTitle>
            </CardHeader>
            <CardContent className="text-xs space-y-2">
              <div className="grid gap-2">
                {[
                  ["cf_scan_network", "Probe /24 subnet for SSH hosts, identify Linux by banner"],
                  ["cf_check_target", "SSH in, check kernel, AEAD config, distro patch status"],
                  ["cf_run_exploit", "Deploy 732-byte PoC via SSH, execute, report root"],
                  ["cf_assess", "Check + exploit in one step"],
                  ["cf_apply_mitigation", "Module blacklist or initcall blacklist, dry-run by default"],
                  ["cf_get_exploit_script", "Return raw PoC as text — pipe over any channel (netcat, curl, web shell)"],
                  ["cf_exploit_local", "Write PoC to local path for manual/container/physical deployment"],
                ].map(([name, desc]) => (
                  <div key={name} className="flex items-start gap-2 p-2 rounded bg-slate-900/30 border border-slate-800">
                    <code className="text-cyan-400 font-mono shrink-0 text-[11px]">{name}</code>
                    <span className="text-slate-400">{desc}</span>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>

          <Card className="border-slate-800 bg-slate-950/50">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Wifi className="h-4 w-4 text-cyan-400" /> Networking Deep Dive
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-2 text-xs text-slate-400">
              <p>This tool connects to SSH on port 22. That requires a direct TCP route.</p>
              <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="border-b border-slate-800">
                      <th className="text-left py-1 pr-2 text-slate-500">Scenario</th>
                      <th className="text-left py-1 pr-2 text-slate-500">Works?</th>
                      <th className="text-left py-1 text-slate-500">Why</th>
                    </tr>
                  </thead>
                  <tbody>
                    {[
                      ["Same home WiFi", "Yes", "AP forwards client-to-client"],
                      ["Phone hotspot", "Yes", "No client isolation"],
                      ["Coffee shop WiFi", "No", "Client isolation blocks peer traffic"],
                      ["Enterprise 802.1X", "Maybe", "VLAN-per-client is common"],
                      ["Tailscale/WireGuard", "Yes", "Virtual network, no NAT issues"],
                      ["Internet (direct)", "Unlikely", "NAT / CGNAT / firewall"],
                    ].map(([scenario, works, why]) => (
                      <tr key={scenario} className="border-b border-slate-800/50">
                        <td className="py-1 pr-2 text-slate-300">{scenario}</td>
                        <td className={`py-1 pr-2 font-medium ${works === "Yes" ? "text-emerald-400" : works === "No" ? "text-red-400" : "text-yellow-400"}`}>{works}</td>
                        <td className="py-1 text-slate-500">{why}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <div className="bg-slate-900/30 p-2 rounded border border-slate-700 mt-2">
                <p className="text-emerald-400 font-medium mb-1">Hotspot is the reliable choice for demos</p>
                <p className="text-slate-500">Phone hotspots (iOS Personal Hotspot, Android Wi-Fi hotspot) do NOT use client isolation. Both laptops get IPs on the same subnet and can communicate freely. This works in a coffee shop, conference hall, park, anywhere with cellular signal.</p>
              </div>
            </CardContent>
          </Card>

          <Card className="border-slate-800 bg-slate-950/50">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Globe className="h-4 w-4 text-cyan-400" /> Alternative Ingress (No SSH)
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-2 text-xs text-slate-400">
              <p>SSH is the default, but the 732-byte PoC can be delivered over any channel:</p>
              {[
                ["Netcat", "Pipe cf_get_exploit_script to a listener on the target: nc TARGET PORT | python3"],
                ["Web shell / RCE", "curl the raw script from a URL and pipe to python3"],
                ["Container exec", "docker exec into a container, use cf_exploit_local to write the script, run it"],
                ["Physical / USB", "Write the 732 bytes to a USB drive, plug in, run from /mnt"],
                ["Copy-paste", "The entire script fits in a single terminal paste"],
              ].map(([method, desc]) => (
                <div key={method} className="flex items-start gap-2">
                  <Terminal className="h-3 w-3 mt-0.5 text-cyan-400 shrink-0" />
                  <div><strong className="text-slate-300">{method}:</strong> {desc}</div>
                </div>
              ))}
            </CardContent>
          </Card>

          <Card className="border-slate-800 bg-slate-950/50">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Smartphone className="h-4 w-4 text-cyan-400" /> Android / IoT / SELinux
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-2 text-xs text-slate-400">
              <p>Android (8.0+, enforcing SELinux) is <strong className="text-emerald-400">protected by policy</strong>,
              not a kernel fix. SELinux blocks AF_ALG socket creation except for the dumpstate process.
              This is an <strong className="text-yellow-400">accidental mitigation</strong> — the policy was written
              for other reasons and happens to block this vector.</p>
              <p>The protection is absent on:</p>
              <ul className="list-disc list-inside space-y-1 ml-2">
                <li><strong>Rooted devices</strong> — root usually sets SELinux permissive</li>
                <li><strong>Custom ROMs</strong> (LineageOS, etc.) — policy varies</li>
                <li><strong>Old / unmaintained devices</strong> — frozen kernel + frozen policy</li>
                <li><strong>Fire tablets / Fire TV</strong> — short update lifespan, then permanently unpatched</li>
                <li><strong>Android TV sticks</strong> — same problem</li>
              </ul>
              <div className="bg-yellow-950/20 border border-yellow-800/50 p-2 rounded mt-1">
                <p className="text-yellow-400 text-[11px]">
                  Note: SELinux policies are plain-text files. AI tools (Xint Code, etc.) can analyze
                  them the same way they analyzed the kernel. The policy mitigation is itself analysable
                  and bypassable by the same class of tool.
                </p>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* ADVANCED */}
        <TabsContent value="advanced" className="space-y-3">
          <Card className="border-slate-800 bg-slate-950/50">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Bug className="h-4 w-4 text-cyan-400" /> Exploit Mechanics
              </CardTitle>
            </CardHeader>
            <CardContent className="text-xs text-slate-400 space-y-2">
              <p>The exploit uses two interacting kernel design defects:</p>
              <div className="space-y-2 mt-2">
                <div className="p-2 rounded bg-slate-900/30 border border-slate-800">
                  <p className="font-medium text-slate-300 mb-1">1. AF_ALG + splice creates page-cache-backed scatterlist entries</p>
                  <p>When a user splices a file into a pipe and feeds it to an AF_ALG AEAD socket, the kernel holds direct references to the file's page cache pages — not copies. For in-place decryption, these pages become writable output regions.</p>
                </div>
                <div className="p-2 rounded bg-slate-900/30 border border-slate-800">
                  <p className="font-medium text-slate-300 mb-1">2. authencesn writes past the AEAD boundary</p>
                  <p>IPsec's Extended Sequence Number wrapper writes 4 bytes at assoclen + cryptlen — past the AEAD tag. In the AF_ALG in-place path, "what follows" is the page cache of the target file. The HMAC fails, recvmsg returns an error, but the write persists.</p>
                </div>
              </div>
              <p className="mt-2">The attacker controls: which file (any readable file), which 4-byte offset, and the value written. The exploit targets /usr/bin/su's page cache to bypass privilege checks.</p>
            </CardContent>
          </Card>

          <Card className="border-slate-800 bg-slate-950/50">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Skull className="h-4 w-4 text-cyan-400" /> Exploit Properties
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 gap-2 text-xs">
                {[
                  ["Requires local execution", "Yes"],
                  ["Race condition", "No — deterministic"],
                  ["Per-distro offsets", "No — same script everywhere"],
                  ["Exploit size", "732 bytes Python 3.10+"],
                  ["On-disk modification", "No — page cache only"],
                  ["Container escape", "Yes — shared page cache"],
                  ["Architecture", "x86_64 + aarch64"],
                  ["Discovery method", "AI-assisted (Xint Code)"],
                ].map(([k, v]) => (
                  <div key={k} className="flex justify-between p-1.5 rounded bg-slate-900/30 border border-slate-800">
                    <span className="text-slate-500">{k}</span>
                    <span className="text-slate-300">{v}</span>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>

          <Card className="border-slate-800 bg-slate-950/50">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Shield className="h-4 w-4 text-cyan-400" /> Mitigation Deep Dive
              </CardTitle>
            </CardHeader>
            <CardContent className="text-xs text-slate-400 space-y-2">
              <p>Two mitigation paths depending on kernel config:</p>
              <div className="space-y-2">
                <div className="p-2 rounded bg-slate-900/30 border border-slate-800">
                  <p className="font-medium text-slate-300 mb-1">Module (=m) — modprobe blacklist (no reboot)</p>
                  <code className="text-cyan-400 font-mono text-[10px] block">echo "install algif_aead /bin/false" &gt; /etc/modprobe.d/disable-algif.conf && rmmod algif_aead</code>
                  <p className="text-slate-500 mt-1">The module cannot be loaded. Affects nothing else (dm-crypt, IPsec, OpenSSL, SSH all work).</p>
                </div>
                <div className="p-2 rounded bg-slate-900/30 border border-slate-800">
                  <p className="font-medium text-slate-300 mb-1">Built-in (=y) — grubby initcall blacklist (reboot required)</p>
                  <code className="text-cyan-400 font-mono text-[10px] block">grubby --update-kernel=ALL --args="initcall_blacklist=algif_aead_init"</code>
                  <p className="text-slate-500 mt-1">The initcall blacklist prevents the vulnerable code from initializing at boot. RHEL-family distros need this; modprobe blacklist silently does nothing on them.</p>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* SAFETY */}
        <TabsContent value="safety" className="space-y-3">
          <Card className="border-red-500 bg-red-950/20">
            <CardContent className="p-3 flex items-start gap-2">
              <AlertTriangle className="h-4 w-4 text-red-500 mt-0.5 shrink-0" />
              <p className="text-xs text-red-400">
                The following warnings apply to every use of this tool. Read all of them before running a test.
              </p>
            </CardContent>
          </Card>

          {safety_warnings.map((w) => (
            <Card key={w.title} className={`border-slate-800 bg-slate-950/50 ${w.severity === "critical" ? "border-l-red-500 border-l-2" : ""}`}>
              <CardHeader className="pb-2">
                <CardTitle className="flex items-center gap-2 text-sm">
                  {w.severity === "critical" ? <Shield className="h-4 w-4 text-red-500" /> : <Terminal className="h-4 w-4 text-slate-400" />}
                  <span className={w.severity === "critical" ? "text-red-400" : "text-slate-200"}>{w.title}</span>
                  <Badge variant={w.severity === "critical" ? "destructive" : "outline"} className="ml-auto">{w.severity}</Badge>
                </CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-xs text-slate-400 leading-relaxed">{w.body}</p>
              </CardContent>
            </Card>
          ))}

          <Card className="border-slate-800 bg-slate-950/50">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <FlaskConical className="h-4 w-4 text-slate-400" /> Ethical Testing Guidelines
              </CardTitle>
            </CardHeader>
            <CardContent>
              <ol className="space-y-1.5 text-xs text-slate-400 list-decimal list-inside">
                <li>Only test systems <strong className="text-red-400">you own</strong> or have <strong className="text-red-400">explicit written permission</strong> to test</li>
                <li>Use <strong>Check Only</strong> first — no exploit deployed, read-only kernel check</li>
                <li>Review results — if the system is already patched, no need to run the exploit</li>
                <li>If vulnerable and authorized, run <strong>Full Assessment</strong></li>
                <li>After confirming the vulnerability, <strong>apply mitigation</strong> or update the kernel</li>
                <li>Verify the fix by re-testing</li>
                <li>Document results for compliance / remediation tracking</li>
                <li>Do not leave the exploit script on the target (<code className="text-cyan-400 font-mono">cleanup=True</code> by default)</li>
              </ol>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
