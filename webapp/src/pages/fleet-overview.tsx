import { useState, useEffect, useCallback } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { PoisonBottle } from "@/common/poison-bottle";
import {
  RadioTower, ShieldCheck, ShieldAlert, AlertTriangle, Network,
  Terminal, RefreshCw, Skull, Server, Loader2,
} from "lucide-react";

interface HostRecord {
  ip: string;
  kernel?: string;
  vulnerable?: boolean;
  patched?: boolean;
  checked_at: string;
  got_root?: boolean;
  note?: string;
}

function safeLoad(): HostRecord[] {
  try { const d = localStorage.getItem("cf-hosts"); return d ? JSON.parse(d) : []; }
  catch { return []; }
}

function safeSave(h: HostRecord[]) {
  try { localStorage.setItem("cf-hosts", JSON.stringify(h)); } catch { /* noop */ }
}

const BACKEND = "http://127.0.0.1:10955";

async function callTool(tool: string, args: Record<string, unknown>) {
  try {
    const r = await fetch(`${BACKEND}/mcp`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: tool, arguments: args } }),
    });
    if (!r.ok) return null;
    const d = await r.json();
    const c = d?.result?.content?.[0]?.text;
    return c ? JSON.parse(c) : null;
  } catch { return null; }
}

export function FleetOverview() {
  const [hosts, setHosts] = useState<HostRecord[]>(() => safeLoad());
  const [scanning, setScanning] = useState(false);
  const [cidr, setCidr] = useState("192.168.1.0/24");
  const [online, setOnline] = useState<boolean | null>(null);

  useEffect(() => {
    fetch(`${BACKEND}/mcp`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} }),
    }).then(() => setOnline(true)).catch(() => setOnline(false));
  }, []);

  useEffect(() => {
    const iv = setInterval(() => {
      const current = safeLoad();
      if (JSON.stringify(current) !== JSON.stringify(hosts)) setHosts(current);
    }, 3000);
    return () => clearInterval(iv);
  }, [hosts]);

  const scan = useCallback(async () => {
    setScanning(true);
    const r = await callTool("cf_scan_network", { cidr, port: 22, timeout: 1.0, max_hosts: 256, only_linux: true });
    if (r?.status === "ok" && r.hosts) {
      const now = new Date().toISOString();
      const existing = safeLoad();
      for (const h of r.hosts) {
        if (!existing.find((e: HostRecord) => e.ip === h.ip)) {
          existing.push({ ip: h.ip, checked_at: now, note: h.banner || "SSH detected" });
        }
      }
      safeSave(existing);
      setHosts([...existing]);
    }
    setScanning(false);
  }, [cidr]);

  const check = useCallback(async (ip: string) => {
    const r = await callTool("cf_check_target", { host: ip, username: "root", port: 22 });
    if (r?.status === "ok") {
      const now = new Date().toISOString();
      const existing = safeLoad().filter((h) => h.ip !== ip);
      existing.push({ ip, kernel: r.kernel, vulnerable: r.vulnerable, patched: r.distro_has_patch, checked_at: now });
      safeSave(existing);
      setHosts([...existing]);
    }
  }, []);

  const own = useCallback(async (ip: string) => {
    const r = await callTool("cf_run_exploit", { host: ip, username: "root", port: 22, cleanup: true });
    if (r?.status === "completed") {
      const now = new Date().toISOString();
      const existing = safeLoad().filter((h) => h.ip !== ip);
      existing.push({ ip, got_root: r.got_root, checked_at: now, note: r.got_root ? "ROOT" : "fail" });
      safeSave(existing);
      setHosts([...existing]);
    }
  }, []);

  const clear = () => { localStorage.removeItem("cf-hosts"); setHosts([]); };

  const v = hosts.filter((h) => h.vulnerable && !h.patched).length;
  const p = hosts.filter((h) => h.patched || h.vulnerable === false).length;
  const u = hosts.filter((h) => h.vulnerable === undefined && !h.got_root).length;
  const o = hosts.filter((h) => h.got_root).length;

  return (
    <div className="min-h-screen bg-slate-950 text-slate-50">
      <div className="max-w-7xl mx-auto px-4 py-6 space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-white">Fleet Overview</h1>
            <p className="text-sm text-slate-400 mt-0.5">Detected Linux hosts and vulnerability status</p>
          </div>
          <div className="flex items-center gap-3">
            <PoisonBottle className="h-6 w-6 text-red-500" />
            {online !== null && (
              <span className={`flex items-center gap-1.5 text-xs ${online ? "text-emerald-400" : "text-red-400"}`}>
                <span className={`h-2 w-2 rounded-full ${online ? "bg-emerald-500" : "bg-red-500"}`} />
                {online ? "Online" : "Offline"}
              </span>
            )}
          </div>
        </div>

        {/* Offline warning */}
        {online === false && (
          <div className="bg-yellow-950/30 border border-yellow-700/50 rounded-lg p-3 flex items-start gap-2 text-sm">
            <AlertTriangle className="h-4 w-4 text-yellow-500 mt-0.5 shrink-0" />
            <div className="text-yellow-400">
              <p className="font-medium">Backend not reachable</p>
              <p className="text-yellow-500/80 mt-0.5 text-xs">Run: <code className="text-cyan-400 font-mono">copy-fail serve --http --port 10955</code></p>
            </div>
          </div>
        )}

        {/* KPI cards */}
        <div className="grid gap-4 grid-cols-2 md:grid-cols-4">
          <Card className="border-red-800 bg-red-950/20">
            <CardHeader className="pb-2"><CardTitle className="text-xs text-red-400 flex items-center gap-1"><ShieldAlert className="h-3 w-3" /> Vulnerable</CardTitle></CardHeader>
            <CardContent><div className="text-3xl font-bold text-red-500">{v}</div><p className="text-xs text-red-400/60 mt-0.5">exploit-ready</p></CardContent>
          </Card>
          <Card className="border-emerald-800 bg-emerald-950/20">
            <CardHeader className="pb-2"><CardTitle className="text-xs text-emerald-400 flex items-center gap-1"><ShieldCheck className="h-3 w-3" /> Patched</CardTitle></CardHeader>
            <CardContent><div className="text-3xl font-bold text-emerald-500">{p}</div><p className="text-xs text-emerald-400/60 mt-0.5">safe</p></CardContent>
          </Card>
          <Card className="border-slate-700 bg-slate-900/50">
            <CardHeader className="pb-2"><CardTitle className="text-xs text-slate-400 flex items-center gap-1"><Server className="h-3 w-3" /> Unknown</CardTitle></CardHeader>
            <CardContent><div className="text-3xl font-bold text-slate-400">{u}</div><p className="text-xs text-slate-500 mt-0.5">not checked</p></CardContent>
          </Card>
          <Card className="border-red-900 bg-red-950/30">
            <CardHeader className="pb-2"><CardTitle className="text-xs text-red-400 flex items-center gap-1"><Skull className="h-3 w-3" /> Owned</CardTitle></CardHeader>
            <CardContent><div className="text-3xl font-bold text-red-500">{o}</div><p className="text-xs text-red-400/60 mt-0.5">root</p></CardContent>
          </Card>
        </div>

        {/* Host list */}
        <Card className="border-slate-800 bg-slate-950/50">
          <CardHeader className="pb-2">
            <div className="flex items-center justify-between">
              <CardTitle className="flex items-center gap-2"><Network className="h-4 w-4 text-slate-400" /> Hosts</CardTitle>
              <div className="flex items-center gap-2">
                <input className="bg-slate-900 border border-slate-800 text-xs text-slate-300 rounded px-2 py-1 h-7 w-28 font-mono" value={cidr} onChange={(e) => setCidr(e.target.value)} placeholder="192.168.1.0/24" />
                <Button size="sm" variant="outline" className="h-7 text-xs border-slate-700" onClick={scan} disabled={scanning}>
                  {scanning ? <Loader2 className="h-3 w-3 mr-1 animate-spin" /> : <RefreshCw className="h-3 w-3 mr-1" />}
                  Scan
                </Button>
                {hosts.length > 0 && <Button size="sm" variant="ghost" className="h-7 text-xs text-slate-500" onClick={clear}>Clear</Button>}
              </div>
            </div>
          </CardHeader>
          <CardContent className="p-0">
            {scanning ? (
              <div className="text-center py-8 text-sm text-slate-500"><Loader2 className="h-4 w-4 inline mr-2 animate-spin" /> Scanning...</div>
            ) : hosts.length === 0 ? (
              <div className="text-center py-12 text-slate-600">
                <RadioTower className="h-10 w-10 mx-auto mb-3 opacity-30" />
                <p className="text-base text-slate-500">No hosts yet</p>
                <p className="text-xs text-slate-600 mt-1">Scan a subnet to find Linux machines</p>
                <Button size="sm" variant="outline" className="mt-3 border-slate-700" onClick={scan}><Network className="h-3 w-3 mr-1" /> Scan {cidr}</Button>
              </div>
            ) : (
              <div className="border-t border-slate-800">
                <div className="divide-y divide-slate-800/50">
                  {hosts.map((h) => (
                    <div key={h.ip} className="flex items-center justify-between px-4 py-2.5 hover:bg-slate-900/30">
                      <div className="flex items-center gap-3 min-w-0 flex-1">
                        <div className={`h-2.5 w-2.5 rounded-full shrink-0 ${
                          h.got_root ? "bg-red-500" :
                          h.vulnerable && !h.patched ? "bg-red-500" :
                          h.patched || h.vulnerable === false ? "bg-emerald-500" : "bg-slate-600"
                        }`} />
                        <div className="min-w-0">
                          <div className="flex items-center gap-2">
                            <span className="text-sm font-mono text-cyan-400">{h.ip}</span>
                            {h.got_root && <Badge variant="destructive" className="text-[10px] px-1 py-0 h-4">OWNED</Badge>}
                            {h.vulnerable && !h.patched && !h.got_root && <Badge variant="destructive" className="text-[10px] px-1 py-0 h-4">VULN</Badge>}
                            {h.patched && <Badge variant="outline" className="text-[10px] px-1 py-0 h-4 border-emerald-700 text-emerald-400">PATCHED</Badge>}
                          </div>
                          <div className="flex items-center gap-2 mt-0.5">
                            {h.kernel && <span className="text-[11px] font-mono text-slate-500">{h.kernel}</span>}
                            <span className="text-[10px] text-slate-600">{new Date(h.checked_at).toLocaleTimeString()}</span>
                            {h.note && <span className="text-[10px] text-slate-600 truncate max-w-[120px]">{h.note}</span>}
                          </div>
                        </div>
                      </div>
                      <div className="flex items-center gap-1 shrink-0 ml-2">
                        <Button size="sm" variant="ghost" className="h-7 w-7 p-0 text-slate-500 hover:text-white" onClick={() => check(h.ip)} title="Check"><Terminal className="h-3.5 w-3.5" /></Button>
                        {(h.vulnerable || h.vulnerable === undefined) && (
                          <Button size="sm" variant="ghost" className="h-7 w-7 p-0 text-red-500 hover:text-red-400" onClick={() => own(h.ip)} title="Exploit"><Skull className="h-3.5 w-3.5" /></Button>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
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
