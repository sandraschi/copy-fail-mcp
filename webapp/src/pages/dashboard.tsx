import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { PoisonBottle } from "@/common/poison-bottle";
import {
  ShieldAlert,
  Terminal,
  AlertTriangle,
  Loader2,
  CheckCircle2,
  XCircle,
  Network,
  Scan,
  Crosshair,
  ShieldCheck,
} from "lucide-react";

type TestPhase = "idle" | "connecting" | "checking" | "exploiting" | "done" | "error";

interface TestResult {
  phase: TestPhase;
  kernel?: string;
  kernel_version?: number[];
  vulnerable?: boolean;
  aead_config?: string;
  mitigation?: string;
  got_root?: boolean;
  output?: string;
  error?: string;
  distro?: string;
}

interface ScanHost {
  ip: string;
  port: number;
  open: boolean;
  is_linux: boolean;
  os_hint: string;
  banner: string;
}

export function TestRunner() {
  const [host, setHost] = useState("");
  const [user, setUser] = useState("root");
  const [port, setPort] = useState("22");
  const [phase, setPhase] = useState<TestPhase>("idle");
  const [result, setResult] = useState<TestResult | null>(null);

  // Scanner state
  const [subnet, setSubnet] = useState("192.168.1.0/24");
  const [scanning, setScanning] = useState(false);
  const [scanResults, setScanResults] = useState<ScanHost[] | null>(null);
  const [scanError, setScanError] = useState("");

  const BACKEND = "";

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

  async function runCheck() {
    setPhase("connecting");
    setResult(null);
    try {
      setPhase("checking");
      const data = await callTool("cf_check_target", {
        host, username: user, port: parseInt(port),
      });
      const content = data?.result?.content?.[0]?.text;
      if (content) {
        const parsed = JSON.parse(content);
        setResult({ phase: "done", ...parsed });
      }
    } catch (e) {
      setResult({ phase: "error", error: String(e) });
    }
  }

  async function runFull() {
    setPhase("connecting");
    setResult(null);
    try {
      setPhase("checking");
      const data = await callTool("cf_assess", {
        host, username: user, port: parseInt(port), force: false, cleanup: true,
      });
      const content = data?.result?.content?.[0]?.text;
      if (content) {
        const parsed = JSON.parse(content);
        setResult({ phase: "done", ...parsed });
      }
    } catch (e) {
      setResult({ phase: "error", error: String(e) });
    }
  }

  async function runScan() {
    setScanning(true);
    setScanResults(null);
    setScanError("");
    try {
      const data = await callTool("cf_scan_network", {
        cidr: subnet,
        port: 22,
        timeout: 1.0,
        max_hosts: 256,
        only_linux: true,
      });
      const content = data?.result?.content?.[0]?.text;
      if (content) {
        const parsed = JSON.parse(content);
        if (parsed.status === "ok") {
          setScanResults(parsed.hosts || []);
        } else {
          setScanError(parsed.error || "Unknown error");
        }
      }
    } catch (e) {
      setScanError(String(e));
    } finally {
      setScanning(false);
    }
  }

  const statusColor = () => {
    if (phase === "idle") return "bg-slate-500";
    if (phase === "error") return "bg-red-500";
    if (phase === "done") {
      if (result?.got_root) return "bg-red-500";
      return "bg-emerald-500";
    }
    return "bg-yellow-500 animate-pulse";
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold tracking-tight text-white">
            Copy Fail Test Runner
          </h2>
          <p className="text-slate-400">
            CVE-2026-31431 Linux kernel LPE assessment
          </p>
        </div>
        <div className="flex items-center gap-2">
          <PoisonBottle className="h-6 w-6 text-red-500" />
          <span className={`h-2 w-2 rounded-full ${statusColor()}`} />
        </div>
      </div>

      <Card className="border-red-900/30 bg-red-950/10">
        <CardContent className="p-3 flex items-start gap-2">
          <AlertTriangle className="h-4 w-4 text-red-500 mt-0.5 shrink-0" />
          <p className="text-xs text-red-400">
            This tool runs a REAL kernel privilege escalation exploit.
            Only use on systems you own or have explicit written permission to test.
            Unauthorized use may be illegal.
          </p>
        </CardContent>
      </Card>

      <Tabs defaultValue="test" className="w-full">
        <TabsList>
          <TabsTrigger value="test">
            <Terminal className="h-3.5 w-3.5 mr-1.5" />
            Test Target
          </TabsTrigger>
          <TabsTrigger value="scan">
            <Scan className="h-3.5 w-3.5 mr-1.5" />
            Network Scan
          </TabsTrigger>
          <TabsTrigger value="mitigate">
            <ShieldCheck className="h-3.5 w-3.5 mr-1.5" />
            Mitigate
          </TabsTrigger>
        </TabsList>

        <TabsContent value="test">
          <div className="grid gap-4 md:grid-cols-3">
            <Card className="border-slate-800 bg-slate-950/50 col-span-1">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Crosshair className="h-4 w-4 text-slate-400" />
                  Target
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <div className="space-y-1">
                  <Label htmlFor="host">Host</Label>
                  <Input id="host" placeholder="192.168.1.100" value={host} onChange={(e) => setHost(e.target.value)} disabled={phase !== "idle"} />
                </div>
                <div className="grid grid-cols-2 gap-2">
                  <div className="space-y-1">
                    <Label htmlFor="user">User</Label>
                    <Input id="user" value={user} onChange={(e) => setUser(e.target.value)} disabled={phase !== "idle"} />
                  </div>
                  <div className="space-y-1">
                    <Label htmlFor="tport">Port</Label>
                    <Input id="tport" value={port} onChange={(e) => setPort(e.target.value)} disabled={phase !== "idle"} />
                  </div>
                </div>
                <div className="space-y-2 pt-2 border-t border-slate-800">
                  <Button className="w-full" onClick={runCheck} disabled={!host || phase !== "idle"}>
                    {phase === "checking" || phase === "connecting" ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <ShieldAlert className="h-4 w-4 mr-2" />}
                    Check Only
                  </Button>
                  <Button variant="destructive" className="w-full" onClick={runFull} disabled={!host || phase !== "idle"}>
                    <Terminal className="h-4 w-4 mr-2" />
                    Full Assessment
                  </Button>
                </div>
                <p className="text-[10px] text-slate-600 text-center">SSH agent forwarding required. No passwords.</p>
              </CardContent>
            </Card>

            <Card className="border-slate-800 bg-slate-950/50 col-span-2">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  Results
                  {(phase === "connecting" || phase === "checking") && <Badge variant="outline" className="ml-2">Working...</Badge>}
                  {phase === "exploiting" && <Badge variant="destructive" className="ml-2">EXPLOITING</Badge>}
                </CardTitle>
              </CardHeader>
              <CardContent>
                {phase === "idle" && !result && (
                  <div className="flex flex-col items-center justify-center py-12 text-slate-600">
                    <PoisonBottle className="h-12 w-12 mb-3 opacity-30" />
                    <p className="text-sm">Enter target details and run a test</p>
                  </div>
                )}
                {(phase === "connecting" || phase === "checking") && (
                  <div className="flex flex-col items-center justify-center py-12">
                    <Loader2 className="h-8 w-8 animate-spin text-slate-400 mb-3" />
                    <p className="text-sm text-slate-400">{phase === "connecting" ? "Connecting via SSH agent..." : "Checking kernel..."}</p>
                  </div>
                )}
                {phase === "exploiting" && (
                  <div className="flex flex-col items-center justify-center py-12">
                    <Loader2 className="h-8 w-8 animate-spin text-red-500 mb-3" />
                    <p className="text-sm text-red-400 font-bold">Running exploit...</p>
                  </div>
                )}
                {result && (
                  <div className="space-y-3">
                    <div className="grid grid-cols-2 gap-2">
                      <div className="p-2 rounded bg-slate-900/50 border border-slate-800">
                        <p className="text-[10px] text-slate-500">Kernel</p>
                        <p className="text-sm font-mono text-cyan-400">{result.kernel || "?"}</p>
                      </div>
                      <div className="p-2 rounded bg-slate-900/50 border border-slate-800">
                        <p className="text-[10px] text-slate-500">AEAD</p>
                        <p className="text-sm font-mono">{result.aead_config || "?"}</p>
                      </div>
                      <div className="p-2 rounded bg-slate-900/50 border border-slate-800">
                        <p className="text-[10px] text-slate-500">Vulnerable</p>
                        {result.vulnerable ? (
                          <div className="flex items-center gap-1"><XCircle className="h-3 w-3 text-red-500" /><span className="text-sm text-red-400">YES</span></div>
                        ) : (
                          <div className="flex items-center gap-1"><CheckCircle2 className="h-3 w-3 text-emerald-500" /><span className="text-sm text-emerald-400">No</span></div>
                        )}
                      </div>
                      <div className="p-2 rounded bg-slate-900/50 border border-slate-800">
                        <p className="text-[10px] text-slate-500">Mitigation</p>
                        <p className="text-sm">{result.mitigation || "?"}</p>
                      </div>
                    </div>
                    {result.got_root !== undefined && (
                      <Card className="border-red-800 bg-red-950/20">
                        <CardContent className="p-3">
                          <div className="flex items-center gap-2">
                            {result.got_root ? (
                              <><span className="text-lg">💀</span><p className="text-sm font-bold text-red-400">ROOT OBTAINED — Vulnerable!</p></>
                            ) : (
                              <><CheckCircle2 className="h-4 w-4 text-emerald-500" /><p className="text-sm text-emerald-400">Exploit did not return root (patched)</p></>
                            )}
                          </div>
                        </CardContent>
                      </Card>
                    )}
                    {result.output && (
                      <div className="space-y-1">
                        <p className="text-[10px] text-slate-500">Output</p>
                        <ScrollArea className="h-[100px]">
                          <pre className="text-xs font-mono text-slate-400 p-2 rounded bg-black/50 border border-slate-800 whitespace-pre-wrap">{result.output}</pre>
                        </ScrollArea>
                      </div>
                    )}
                    {result.error && <div className="p-2 rounded bg-red-950/20 border border-red-800"><p className="text-xs text-red-400">{result.error}</p></div>}
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="scan">
          <div className="grid gap-4 md:grid-cols-3">
            <Card className="border-slate-800 bg-slate-950/50">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Network className="h-4 w-4 text-slate-400" />
                  Network Scan
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <div className="space-y-1">
                  <Label htmlFor="subnet">Subnet (CIDR)</Label>
                  <Input id="subnet" placeholder="192.168.1.0/24" value={subnet} onChange={(e) => setSubnet(e.target.value)} disabled={scanning} />
                </div>
                <Button className="w-full" onClick={runScan} disabled={scanning || !subnet}>
                  {scanning ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <Scan className="h-4 w-4 mr-2" />}
                  {scanning ? "Scanning..." : "Scan Subnet"}
                </Button>
                <p className="text-[10px] text-slate-600">Async TCP connect on port 22. No special permissions needed. ~2-5 min for /24.</p>
              </CardContent>
            </Card>

            <Card className="border-slate-800 bg-slate-950/50 col-span-2">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  Discovered Hosts
                  {scanResults && <Badge className="ml-2">{scanResults.length} found</Badge>}
                </CardTitle>
              </CardHeader>
              <CardContent>
                {!scanResults && !scanning && !scanError && (
                  <div className="flex flex-col items-center justify-center py-12 text-slate-600">
                    <Network className="h-12 w-12 mb-3 opacity-30" />
                    <p className="text-sm">Enter a subnet and scan</p>
                  </div>
                )}
                {scanning && (
                  <div className="flex flex-col items-center justify-center py-12">
                    <Loader2 className="h-8 w-8 animate-spin text-slate-400 mb-3" />
                    <p className="text-sm text-slate-400">Scanning {subnet} on port 22...</p>
                  </div>
                )}
                {scanError && <div className="p-2 rounded bg-red-950/20 border border-red-800"><p className="text-xs text-red-400">{scanError}</p></div>}
                {scanResults && (
                  <ScrollArea className="h-[300px]">
                    <div className="space-y-1">
                      {scanResults.map((h) => (
                        <div key={h.ip} className="flex items-center justify-between p-2 rounded bg-slate-900/30 border border-slate-800">
                          <div className="flex items-center gap-3">
                            <div className={`h-2 w-2 rounded-full ${h.is_linux ? "bg-red-500" : "bg-slate-600"}`} />
                            <span className="text-sm font-mono text-cyan-400">{h.ip}</span>
                            {h.is_linux && <Badge variant="destructive" className="text-[10px]">Linux</Badge>}
                          </div>
                          <div className="flex items-center gap-2">
                            <span className="text-[10px] text-slate-500 font-mono truncate max-w-[200px]">{h.banner || "unknown"}</span>
                            <Button size="sm" variant="ghost" className="h-6 text-xs" onClick={() => { setHost(h.ip); setPhase("idle"); }}>
                              Use
                            </Button>
                          </div>
                        </div>
                      ))}
                      {scanResults.length === 0 && <p className="text-sm text-slate-500 text-center py-8">No SSH hosts found on {subnet}</p>}
                    </div>
                  </ScrollArea>
                )}
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="mitigate">
          <div className="grid gap-4 md:grid-cols-3">
            <Card className="border-slate-800 bg-slate-950/50">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <ShieldCheck className="h-4 w-4 text-slate-400" />
                  Mitigation
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <div className="space-y-1">
                  <Label htmlFor="mhost">Host</Label>
                  <Input id="mhost" placeholder="192.168.1.100" value={host} onChange={(e) => setHost(e.target.value)} />
                </div>
                <div className="grid grid-cols-2 gap-2">
                  <div className="space-y-1">
                    <Label htmlFor="muser">User</Label>
                    <Input id="muser" value={user} onChange={(e) => setUser(e.target.value)} />
                  </div>
                  <div className="space-y-1">
                    <Label htmlFor="mport">Port</Label>
                    <Input id="mport" value={port} onChange={(e) => setPort(e.target.value)} />
                  </div>
                </div>
                <Button className="w-full" onClick={async () => {
                  setPhase("checking");
                  try {
                    const data = await callTool("cf_apply_mitigation", { host, username: user, port: parseInt(port), dry_run: true });
                    const content = data?.result?.content?.[0]?.text;
                    if (content) setResult({ phase: "done", ...JSON.parse(content) });
                  } catch (e) { setResult({ phase: "error", error: String(e) }); }
                }} disabled={!host || phase !== "idle"}>
                  <ShieldCheck className="h-4 w-4 mr-2" />
                  Check Mitigation
                </Button>
                <p className="text-[10px] text-slate-600">Dry-run by default. Shows commands without executing.</p>
              </CardContent>
            </Card>

            <Card className="border-slate-800 bg-slate-950/50 col-span-2">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">Results</CardTitle>
              </CardHeader>
              <CardContent>
                {result?.mitigation_type && (
                  <div className="space-y-3">
                    <div className="grid grid-cols-2 gap-2">
                      <div className="p-2 rounded bg-slate-900/50 border border-slate-800">
                        <p className="text-[10px] text-slate-500">Type</p>
                        <p className="text-sm font-mono text-cyan-400">{result.mitigation_type}</p>
                      </div>
                      <div className="p-2 rounded bg-slate-900/50 border border-slate-800">
                        <p className="text-[10px] text-slate-500">Reboot Required</p>
                        <p className="text-sm">{result.reboot_required ? "Yes" : "No"}</p>
                      </div>
                    </div>
                    {result.commands && (
                      <div className="space-y-1">
                        <p className="text-[10px] text-slate-500">Commands</p>
                        <div className="space-y-1">
                          {result.commands.map((cmd: string, i: number) => (
                            <pre key={i} className="text-xs font-mono text-slate-300 p-2 rounded bg-black/50 border border-slate-800">{cmd}</pre>
                          ))}
                        </div>
                      </div>
                    )}
                    {result.status === "already_mitigated" && (
                      <div className="p-2 rounded bg-emerald-950/20 border border-emerald-800">
                        <p className="text-xs text-emerald-400">Already mitigated — no action needed</p>
                      </div>
                    )}
                  </div>
                )}
                {!result && phase === "idle" && (
                  <div className="flex flex-col items-center justify-center py-12 text-slate-600">
                    <ShieldCheck className="h-12 w-12 mb-3 opacity-30" />
                    <p className="text-sm">Enter target and check mitigation status</p>
                  </div>
                )}
                {result?.error && <div className="p-2 rounded bg-red-950/20 border border-red-800"><p className="text-xs text-red-400">{result.error}</p></div>}
              </CardContent>
            </Card>
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
}
