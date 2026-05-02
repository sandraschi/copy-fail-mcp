import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { PoisonBottle } from "@/common/poison-bottle";
import { ExternalLink, Bug, Search, FileText } from "lucide-react";

const refs = [
  { label: "NVD Entry", url: "https://nvd.nist.gov/vuln/detail/CVE-2026-31431" },
  { label: "Theori/Xint Writeup", url: "https://xint.io/blog/copy-fail-linux-distributions" },
  { label: "PoC Repo", url: "https://github.com/theori-io/copy-fail-CVE-2026-31431" },
  { label: "CERT-EU Advisory", url: "https://cert.europa.eu/publications/security-advisories/2026-005/" },
  { label: "Microsoft Security Blog", url: "https://www.microsoft.com/en-us/security/blog/2026/05/01/cve-2026-31431-copy-fail-" },
  { label: "AlmaLinux Patch Post", url: "https://almalinux.org/blog/2026-05-01-cve-2026-31431-copy-fail/" },
];

const timeline = [
  { date: "2017", event: "Bug introduced: kernel optimization to authencesn scratch-write logic" },
  { date: "2026-04-29", event: "Disclosed by Theori / Xint Code Research (AI-assisted discovery)" },
  { date: "2026-04-29", event: "Upstream patch committed (a664bf3d603d)" },
  { date: "2026-05-01", event: "Major distros patch: Ubuntu, RHEL, AlmaLinux, Debian, SUSE" },
  { date: "2026-05-01", event: "CISA adds to Known Exploited Vulnerabilities catalog" },
];

export function About() {
  return (
    <div className="space-y-6">
      <div className="flex items-center gap-4">
        <PoisonBottle className="h-10 w-10 text-red-500" />
        <div>
          <h2 className="text-2xl font-bold tracking-tight text-white">
            CVE-2026-31431
          </h2>
          <p className="text-slate-400 font-mono text-sm">
            &ldquo;Copy Fail&rdquo; — Linux Kernel LPE
          </p>
        </div>
        <Badge variant="destructive" className="ml-auto">CVSS 7.8 (High)</Badge>
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        <Card className="border-slate-800 bg-slate-950/50">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Bug className="h-4 w-4 text-red-400" /> Summary
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-2 text-xs text-slate-400 leading-relaxed">
            <p>
              A logic bug in the Linux kernel's <code className="text-cyan-400">authencesn</code> crypto
              template allows any unprivileged local user to write 4 controlled bytes into the kernel
              page cache of any readable file, without leaving a trace on disk.
            </p>
            <p>
              A 732-byte Python script exploits this by corrupting <code className="text-cyan-400">/usr/bin/su</code>
              in memory to gain root. No race conditions, no per-distro offsets, no compiled payloads.
            </p>
            <p>
              Affects all Linux kernels built since 2017 (kernel ≥ 4.14).
              Confirmed on x86_64 and aarch64.
            </p>
          </CardContent>
        </Card>

        <Card className="border-slate-800 bg-slate-950/50">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Search className="h-4 w-4 text-cyan-400" /> Discovery Context
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-2 text-xs text-slate-400 leading-relaxed">
            <p>
              Found by Theori researcher <strong>Taeyang Lee</strong> using their{" "}
              <strong>Xint Code</strong> AI-native SAST platform — one operator prompt,
              ~1 hour of scan time against the Linux <code className="text-cyan-400">crypto/</code> subsystem.
            </p>
            <p className="font-bold text-yellow-500">
              First publicly confirmed kernel-grade LPE found via AI-assisted automated scan
              with no human code review in the loop during discovery.
            </p>
            <p>
              The bug existed for 9 years and survived all prior human review, static analysis,
              and fuzzing — because it requires cross-subsystem reasoning (AF_ALG socket
              provenance + authencesn scratch-write behaviour) simultaneously.
            </p>
          </CardContent>
        </Card>

        <Card className="border-slate-800 bg-slate-950/50 col-span-2">
          <CardHeader>
            <CardTitle>Timeline</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-0">
              {timeline.map((t, i) => (
                <div key={i} className="flex gap-3 py-2 border-b border-slate-800 last:border-0">
                  <span className="text-xs font-mono text-slate-500 w-24 shrink-0">{t.date}</span>
                  <span className="text-xs text-slate-300">{t.event}</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>

        <Card className="border-slate-800 bg-slate-950/50">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <FileText className="h-4 w-4 text-slate-400" /> Exploit Properties
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-1 text-xs">
              {[
                ["Requires local execution", "Yes — must run code as unprivileged user"],
                ["Race condition", "No — deterministic"],
                ["Per-distro offsets", "No — same script everywhere"],
                ["Exploit size", "732 bytes (Python 3.10+ stdlib only)"],
                ["On-disk modification", "No — page cache only"],
                ["Container escape", "Yes — shared page cache on shared kernels"],
                ["Architecture", "x86_64 and aarch64 confirmed"],
              ].map(([k, v]) => (
                <div key={k} className="flex justify-between py-1 border-b border-slate-800 last:border-0">
                  <span className="text-slate-500">{k}</span>
                  <span className="text-slate-300 text-right">{v}</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>

        <Card className="border-slate-800 bg-slate-950/50">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <ExternalLink className="h-4 w-4 text-slate-400" /> References
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-1">
            {refs.map((r) => (
              <a
                key={r.label}
                href={r.url}
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center gap-2 text-xs text-blue-400 hover:text-blue-300 py-1"
              >
                <ExternalLink className="h-3 w-3 shrink-0" />
                {r.label}
              </a>
            ))}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
