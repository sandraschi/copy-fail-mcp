import { useState, useEffect, useCallback } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  RadioTower, ShieldCheck, ShieldAlert, AlertTriangle, Network,
  Terminal, RefreshCw, Skull, Server, Loader2,
} from "lucide-react";

interface Host {
  ip: string; kernel?: string; vulnerable?: boolean; patched?: boolean;
  got_root?: boolean; checked_at: string; note?: string;
}

function load(): Host[] { try { const d = localStorage.getItem("cf-hosts"); return d ? JSON.parse(d) : []; } catch { return []; } }
function save(h: Host[]) { try { localStorage.setItem("cf-hosts", JSON.stringify(h)); } catch { /* */ } }

const BACKEND = "";

async function call(tool: string, args: Record<string, unknown>) {
  try {
    const r = await fetch(`${BACKEND}/mcp`, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: tool, arguments: args } }),
    });
    if (!r.ok) return null;
    const d = await r.json();
    const c = d?.result?.content?.[0]?.text;
    return c ? JSON.parse(c) : null;
  } catch { return null; }
}

export function Targets() {
  const [hosts, setHosts] = useState<Host[]>(() => load());
  const [scanning, setScanning] = useState(false);
  const [wslDetecting, setWslDetecting] = useState(false);
  const [cidr, setCidr] = useState("192.168.1.0/24");
  const [scanProgress, setScanProgress] = useState("");
  const [online, setOnline] = useState<boolean | null>(null);

  useEffect(() => {
    fetch(`${BACKEND}/mcp`, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} }),
    }).then(() => setOnline(true)).catch(() => setOnline(false));
  }, []);

  useEffect(() => {
    const iv = setInterval(() => { const c = load(); if (JSON.stringify(c) !== JSON.stringify(hosts)) setHosts(c); }, 3000);
    return () => clearInterval(iv);
  }, [hosts]);

  const runScan = useCallback(async () => {
    setScanning(true);
    setScanProgress("Probing SSH port 22...");
    const r = await call("cf_scan_network", { cidr, port: 22, timeout: 1.0, max_hosts: 256, only_linux: true });
    setScanProgress("");
    setScanning(false);
    if (r?.status === "ok" && r.hosts) {
      const now = new Date().toISOString();
      const existing = load();
      for (const h of r.hosts) {
        if (!existing.find((e) => e.ip === h.ip)) {
          existing.push({ ip: h.ip, checked_at: now, note: h.banner || "SSH detected" });
        }
      }
      save(existing);
      setHosts([...existing]);
    }
  }, [cidr]);

  const detectWsl = useCallback(async () => {
    setWslDetecting(true);
    const r = await call("cf_detect_local_wsl", {});
    setWslDetecting(false);
    if (r?.status === "ok" && r.hosts?.length > 0) {
      const now = new Date().toISOString();
      const existing = load();
      for (const h of r.hosts) {
        const ip = h.ip as string;
        if (!existing.find((e) => e.ip === ip)) {
          existing.push({ ip, checked_at: now, note: `WSL: ${h.distro}` });
        }
      }
      save(existing);
      setHosts([...existing]);
    }
  }, []);

  const check = useCallback(async (ip: string) => {
    const r = await call("cf_check_target", { host: ip, username: "root", port: 22 });
    if (r?.status === "ok") {
      const now = new Date().toISOString();
      const existing = load().filter((h) => h.ip !== ip);
      existing.push({ ip, kernel: r.kernel, vulnerable: r.vulnerable, checked_at: now });
      save(existing);
      setHosts([...existing]);
    }
  }, []);

  const own = useCallback(async (ip: string) => {
    const r = await call("cf_run_exploit", { host: ip, username: "root", port: 22, cleanup: true });
    if (r?.status === "completed") {
      const now = new Date().toISOString();
      const existing = load().filter((h) => h.ip !== ip);
      existing.push({ ip, got_root: r.got_root, checked_at: now, note: r.got_root ? "ROOT" : "no root" });
      save(existing);
      setHosts([...existing]);
    }
  }, []);

  const clear = () => { localStorage.removeItem("cf-hosts"); setHosts([]); };

  const v = hosts.filter((h) => h.vulnerable && !h.patched).length;
  const p = hosts.filter((h) => h.patched).length;
  const u = hosts.filter((h) => !h.vulnerable && !h.patched && !h.got_root).length;
  const o = hosts.filter((h) => h.got_root).length;

  return (
    <div className="min-h-screen bg-slate-950 text-slate-50">
      <div className="max-w-7xl mx-auto px-4 py-6 space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-white">Targets</h1>
            <p className="text-sm text-slate-400 mt-0.5">Discovered Linux hosts and vulnerability status</p>
          </div>
          {online !== null && (
            <span className={`flex items-center gap-1.5 text-xs ${online ? "text-emerald-400" : "text-red-400"}`}>
              <span className={`h-2 w-2 rounded-full ${online ? "bg-emerald-500" : "bg-red-500"}`} />
              {online ? "Backend online" : "Backend offline"}
            </span>
          )}
        </div>

        {online === false && (
          <div className="bg-yellow-950/30 border border-yellow-700/50 rounded-lg p-3 flex items-start gap-2 text-sm">
            <AlertTriangle className="h-4 w-4 text-yellow-500 mt-0.5 shrink-0" />
            <div className="text-yellow-400">
              <p className="font-medium">Backend not reachable</p>
              <p className="text-yellow-500/80 mt-0.5 text-xs">Run: <code className="text-cyan-400 font-mono">copy-fail serve --http --port 10955</code></p>
            </div>
          </div>
        )}

        <div className="grid gap-4 grid-cols-2 md:grid-cols-4">
          {[
            { label: "Vulnerable", count: v, color: "text-red-500", border: "border-red-800", bg: "bg-red-950/20", icon: ShieldAlert, iconColor: "text-red-400" },
            { label: "Patched", count: p, color: "text-emerald-500", border: "border-emerald-800", bg: "bg-emerald-950/20", icon: ShieldCheck, iconColor: "text-emerald-400" },
            { label: "Unknown", count: u, color: "text-slate-400", border: "border-slate-700", bg: "bg-slate-900/50", icon: Server, iconColor: "text-slate-400" },
            { label: "Owned", count: o, color: "text-red-500", border: "border-red-900", bg: "bg-red-950/30", icon: Skull, iconColor: "text-red-400" },
          ].map(({ label, count, color, border, bg, icon: Icon, iconColor }) => (
            <Card key={label} className={`${border} ${bg}`}>
              <CardHeader className="pb-2">
                <CardTitle className={`text-xs ${iconColor} flex items-center gap-1`}>
                  <Icon className="h-3.5 w-3.5" /> {label}
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className={`text-3xl font-bold ${color}`}>{count}</div>
              </CardContent>
            </Card>
          ))}
        </div>

<Card className="border-slate-800 bg-slate-950/50">
  <CardHeader className="pb-2">
    <div className="flex items-center justify-between">
      <CardTitle className="flex items-center gap-2"><Network className="h-4 w-4 text-slate-400" /> Targets ({hosts.length})</CardTitle>
      <div className="flex items-center gap-2">
        <input className="bg-slate-900 border border-slate-800 text-xs text-slate-300 rounded px-2 py-1 h-7 w-28 font-mono" value={cidr} onChange={(e) => setCidr(e.target.value)} placeholder="192.168.1.0/24" />
        {scanning ? (
          <span className="flex items-center gap-1.5 text-xs text-slate-400"><Loader2 className="h-3 w-3 animate-spin" /> Scanning...</span>
        ) : (
          <div className="flex items-center gap-1.5">
            <Button size="sm" variant="outline" className="h-7 text-xs border-slate-700" onClick={runScan}>
              <RefreshCw className="h-3 w-3 mr-1" /> Scan
            </Button>
            <Button size="sm" variant="outline" className="h-7 text-xs border-slate-700" onClick={detectWsl} disabled={wslDetecting}>
              {wslDetecting ? <Loader2 className="h-3 w-3 mr-1 animate-spin" /> : <Terminal className="h-3 w-3 mr-1" />}
              WSL
            </Button>
          </div>
        )}
        {hosts.length > 0 && !scanning && (
          <Button size="sm" variant="ghost" className="h-7 text-xs text-slate-500" onClick={clear}>Clear</Button>
        )}
      </div>
    </div>
  </CardHeader>
  <CardContent>
    {scanning && (
      <div className="flex items-center justify-center py-8 text-sm text-slate-500">
        <Loader2 className="h-4 w-4 mr-2 animate-spin" /> {scanProgress || "Scanning subnet..."}
      </div>
    )}
    {!scanning && hosts.length === 0 && (
      <div className="flex flex-col items-center justify-center py-12 text-slate-600">
        <RadioTower className="h-12 w-12 mb-3 opacity-30" />
        <p className="text-base text-slate-500">No targets discovered yet</p>
        <p className="text-xs text-slate-600 mt-1">Scan a subnet to find Linux hosts with SSH open</p>
        <Button size="sm" variant="outline" className="mt-3 border-slate-700 text-xs" onClick={runScan}>
          <Network className="h-3 w-3 mr-1" /> Scan
        </Button>
      </div>
    )}
    {!scanning && hosts.length > 0 && (
      <div className="grid gap-3 md:grid-cols-2">
        {hosts.map((h) => (
          <Card key={h.ip} className={`border ${
            h.got_root ? "border-red-700 bg-red-950/10" :
            h.vulnerable ? "border-red-900/50 bg-red-950/5" :
            h.patched || h.vulnerable === false ? "border-emerald-900/50 bg-emerald-950/5" :
            "border-slate-800 bg-slate-950/50"
          }`}>
            <CardContent className="p-3">
              <div className="flex items-start justify-between">
                <div className="flex items-center gap-2 min-w-0">
                  <div className={`h-3 w-3 rounded-full shrink-0 mt-0.5 ${
                    h.got_root ? "bg-red-500" :
                    h.vulnerable ? "bg-red-500" :
                    h.patched || h.vulnerable === false ? "bg-emerald-500" :
                    "bg-slate-600"
                  }`} />
                  <div>
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-base font-mono text-cyan-400 font-medium">{h.ip}</span>
                      {h.got_root && <Badge variant="destructive" className="text-[10px]">OWNED</Badge>}
                      {h.vulnerable && !h.got_root && <Badge variant="destructive" className="text-[10px]">VULN</Badge>}
                      {h.patched && <Badge className="text-[10px] bg-emerald-900/30 text-emerald-400 border-emerald-700">PATCHED</Badge>}
                    </div>
                    <div className="flex items-center gap-3 mt-1 flex-wrap text-xs">
                      {h.kernel && <span className="font-mono text-cyan-400 text-[11px]">{h.kernel}</span>}
                      {h.checked_at && <span className="text-slate-600 text-[10px]">{new Date(h.checked_at).toLocaleString()}</span>}
                    </div>
                    {h.note && (
                      <p className="text-[10px] text-slate-600 mt-1 font-mono truncate max-w-[300px]">{h.note}</p>
                    )}
                  </div>
                </div>
              </div>
              <div className="flex items-center gap-2 mt-3 pt-2 border-t border-slate-800">
                <Button size="sm" variant="outline" className="h-7 text-[10px] border-slate-700 text-slate-400" onClick={() => check(h.ip)}>
                  <Terminal className="h-3 w-3 mr-1" /> Check
                </Button>
                <Button size="sm" variant="destructive" className="h-7 text-[10px]" onClick={() => own(h.ip)}>
                  <Skull className="h-3 w-3 mr-1" /> Exploit
                </Button>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    )}
  </CardContent>
</Card>

        {hosts.length > 0 && (
          <div className="flex items-center gap-4 text-xs text-slate-500 border-t border-slate-800 pt-4">
            <span className="flex items-center gap-1"><span className="h-2 w-2 rounded-full bg-red-500" /> Vulnerable</span>
            <span className="flex items-center gap-1"><span className="h-2 w-2 rounded-full bg-emerald-500" /> Patched</span>
            <span className="flex items-center gap-1"><span className="h-2 w-2 rounded-full bg-slate-600" /> Unknown</span>
            <span className="ml-auto">{hosts.length} host{hosts.length !== 1 ? "s" : ""}</span>
          </div>
        )}
      </div>
    </div>
  );
}
