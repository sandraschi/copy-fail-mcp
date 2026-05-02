import { useState, useEffect } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { PoisonBottle } from "@/common/poison-bottle";
import {
  RadioTower,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  Network,
  Terminal,
  CheckCircle2,
  XCircle,
  RefreshCw,
  Skull,
  Server,
  Loader2,
} from "lucide-react";

interface HostRecord {
  ip: string;
  hostname?: string;
  kernel?: string;
  vulnerable?: boolean;
  patched?: boolean;
  checked_at: string;
  got_root?: boolean;
  note?: string;
}

function loadHosts(): HostRecord[] {
  try {
    return JSON.parse(localStorage.getItem("cf-hosts") || "[]");
  } catch {
    return [];
  }
}

function saveHosts(hosts: HostRecord[]) {
  localStorage.setItem("cf-hosts", JSON.stringify(hosts));
}

export function FleetOverview() {
  const [hosts, setHosts] = useState<HostRecord[]>(loadHosts);
  const [scanning, setScanning] = useState(false);
  const [scanCidr, setScanCidr] = useState("192.168.1.0/24");

  useEffect(() => {
    const interval = setInterval(() => {
      const current = loadHosts();
      if (JSON.stringify(current) !== JSON.stringify(hosts)) {
        setHosts(current);
      }
    }, 2000);
    return () => clearInterval(interval);
  }, [hosts]);

  const BACKEND = "http://127.0.0.1:10955";

  async function callTool(tool: string, args: Record<string, unknown>) {
    const resp = await fetch(`${BACKEND}/mcp`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: { name: tool, arguments: args },
      }),
    });
    return resp.json();
  }

  async function runScan() {
    setScanning(true);
    try {
      const data = await callTool("cf_scan_network", {
        cidr: scanCidr,
        port: 22,
        timeout: 1.0,
        max_hosts: 256,
        only_linux: true,
      });
      const content = data?.result?.content?.[0]?.text;
      if (content) {
        const parsed = JSON.parse(content);
        if (parsed.status === "ok" && parsed.hosts) {
          const now = new Date().toISOString();
          const existing = loadHosts();
          for (const h of parsed.hosts) {
            const found = existing.find((e) => e.ip === h.ip);
            if (!found) {
              existing.push({
                ip: h.ip,
                checked_at: now,
                note: `SSH banner: ${h.banner || "unknown"}`,
              });
            }
          }
          saveHosts(existing);
          setHosts(existing);
        }
      }
    } catch (e) {
      console.error("Scan failed:", e);
    } finally {
      setScanning(false);
    }
  }

  async function quickCheck(ip: string) {
    try {
      const data = await callTool("cf_check_target", {
        host: ip,
        username: "root",
        port: 22,
      });
      const content = data?.result?.content?.[0]?.text;
      if (content) {
        const parsed = JSON.parse(content);
        if (parsed.status === "ok") {
          const now = new Date().toISOString();
          const existing = loadHosts().filter((h) => h.ip !== ip);
          existing.push({
            ip,
            kernel: parsed.kernel,
            vulnerable: parsed.vulnerable,
            patched: parsed.distro_has_patch,
            checked_at: now,
          });
          saveHosts(existing);
          setHosts(existing);
        }
      }
    } catch (e) {
      console.error("Check failed:", e);
    }
  }

  async function quickExploit(ip: string) {
    try {
      const data = await callTool("cf_run_exploit", {
        host: ip,
        username: "root",
        port: 22,
        cleanup: true,
      });
      const content = data?.result?.content?.[0]?.text;
      if (content) {
        const parsed = JSON.parse(content);
        const now = new Date().toISOString();
        const existing = loadHosts().filter((h) => h.ip !== ip);
        existing.push({
          ip,
          got_root: parsed.got_root,
          checked_at: now,
          note: parsed.got_root ? "ROOT OBTAINED" : parsed.output?.slice(0, 100),
        });
        saveHosts(existing);
        setHosts(existing);
      }
    } catch {
      // ignore
    }
  }

  const clearHosts = () => {
    localStorage.removeItem("cf-hosts");
    setHosts([]);
  };

  const vulnerableCount = hosts.filter((h) => h.vulnerable && !h.patched).length;
  const patchedCount = hosts.filter((h) => h.patched || (h.vulnerable === false)).length;
  const unknownCount = hosts.filter((h) => h.vulnerable === undefined).length;
  const ownedCount = hosts.filter((h) => h.got_root).length;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold tracking-tight text-white">Fleet Overview</h2>
          <p className="text-slate-400">Detected Linux hosts and vulnerability status</p>
        </div>
        <PoisonBottle className="h-6 w-6 text-red-500" />
      </div>

      <div className="grid gap-4 md:grid-cols-4">
        <Card className="border-red-800 bg-red-950/20">
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-2 text-xs text-red-400">
              <ShieldAlert className="h-3.5 w-3.5" /> Vulnerable
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-red-500">{vulnerableCount}</div>
            <p className="text-xs text-red-400/60">unpatched, exploit-ready</p>
          </CardContent>
        </Card>
        <Card className="border-emerald-800 bg-emerald-950/20">
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-2 text-xs text-emerald-400">
              <ShieldCheck className="h-3.5 w-3.5" /> Patched
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-emerald-500">{patchedCount}</div>
            <p className="text-xs text-emerald-400/60">safe or mitigated</p>
          </CardContent>
        </Card>
        <Card className="border-slate-700 bg-slate-900/50">
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-2 text-xs text-slate-400">
              <Server className="h-3.5 w-3.5" /> Unknown
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-slate-400">{unknownCount}</div>
            <p className="text-xs text-slate-500">not yet checked</p>
          </CardContent>
        </Card>
        <Card className="border-red-900 bg-red-950/30">
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-2 text-xs text-red-400">
              <Skull className="h-3.5 w-3.5" /> Owned
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-red-500">{ownedCount}</div>
            <p className="text-xs text-red-400/60">root obtained</p>
          </CardContent>
        </Card>
      </div>

      <Card className="border-slate-800 bg-slate-950/50">
        <CardHeader className="pb-2">
          <div className="flex items-center justify-between">
            <CardTitle className="flex items-center gap-2">
              <Network className="h-4 w-4 text-slate-400" /> Discovered Hosts
            </CardTitle>
            <div className="flex items-center gap-2">
              <Button size="sm" variant="outline" className="h-7 text-xs border-slate-700" onClick={runScan} disabled={scanning}>
                {scanning ? <Loader2 className="h-3 w-3 mr-1 animate-spin" /> : <RefreshCw className="h-3 w-3 mr-1" />}
                Scan
              </Button>
              <Button size="sm" variant="ghost" className="h-7 text-xs text-slate-500" onClick={clearHosts}>Clear</Button>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {hosts.length === 0 && (
            <div className="flex flex-col items-center justify-center py-12 text-slate-600">
              <RadioTower className="h-12 w-12 mb-3 opacity-30" />
              <p className="text-sm">No hosts discovered yet</p>
              <p className="text-xs text-slate-600 mt-1">Scan a subnet or add hosts from the Test Runner</p>
              <Button size="sm" variant="outline" className="mt-3 border-slate-700" onClick={runScan} disabled={scanning}>
                {scanning ? <Loader2 className="h-3 w-3 mr-1 animate-spin" /> : <Network className="h-3 w-3 mr-1" />}
                Scan 192.168.1.0/24
              </Button>
            </div>
          )}
          {hosts.length > 0 && (
            <ScrollArea className="h-[400px]">
              <div className="space-y-1">
                {hosts.map((h) => (
                  <div key={h.ip} className="flex items-center justify-between p-2.5 rounded bg-slate-900/30 border border-slate-800 hover:bg-slate-900/50">
                    <div className="flex items-center gap-3 min-w-0 flex-1">
                      <div className={`h-2.5 w-2.5 rounded-full shrink-0 ${
                        h.got_root ? "bg-red-500 animate-pulse" :
                        h.vulnerable && !h.patched ? "bg-red-500" :
                        h.patched ? "bg-emerald-500" :
                        h.vulnerable === false ? "bg-emerald-500" :
                        "bg-slate-600"
                      }`} />
                      <div className="min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="text-sm font-mono text-cyan-400">{h.ip}</span>
                          {h.got_root && <Badge variant="destructive" className="text-[9px] px-1 py-0 h-4">OWNED</Badge>}
                          {h.vulnerable && !h.patched && !h.got_root && <Badge variant="destructive" className="text-[9px] px-1 py-0 h-4">VULN</Badge>}
                          {h.patched && <Badge variant="outline" className="text-[9px] px-1 py-0 h-4 border-emerald-700 text-emerald-400">PATCHED</Badge>}
                        </div>
                        <div className="flex items-center gap-2 mt-0.5">
                          {h.kernel && <span className="text-[10px] font-mono text-slate-500">{h.kernel}</span>}
                          <span className="text-[9px] text-slate-600">{new Date(h.checked_at).toLocaleTimeString()}</span>
                          {h.note && <span className="text-[9px] text-slate-600 truncate max-w-[150px]">{h.note}</span>}
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center gap-1 shrink-0 ml-2">
                      <Button size="sm" variant="ghost" className="h-6 w-6 p-0 text-slate-500" onClick={() => quickCheck(h.ip)} title="Quick check">
                        <Terminal className="h-3 w-3" />
                      </Button>
                      {(h.vulnerable || h.vulnerable === undefined) && (
                        <Button size="sm" variant="ghost" className="h-6 w-6 p-0 text-red-500" onClick={() => quickExploit(h.ip)} title="Quick exploit">
                          <Skull className="h-3 w-3" />
                        </Button>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </ScrollArea>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
