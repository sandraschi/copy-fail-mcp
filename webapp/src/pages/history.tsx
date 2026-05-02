import { Card, CardContent } from "@/components/ui/card";
import { PoisonBottle } from "@/common/poison-bottle";
import { History, Shield, Skull, FileText } from "lucide-react";

export function History() {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold tracking-tight text-white">Test History</h2>
          <p className="text-slate-400">Past assessments and exploit runs</p>
        </div>
      </div>

      <Card className="border-slate-800 bg-slate-950/50">
        <CardContent className="flex flex-col items-center justify-center py-16 text-center">
          <PoisonBottle className="h-12 w-12 text-slate-700 mb-4" />
          <History className="h-8 w-8 text-slate-700 mb-3" />
          <h3 className="text-lg font-medium text-slate-500">No Tests Run Yet</h3>
          <p className="text-sm text-slate-600 max-w-md mt-1">
            Results from the Test Runner will appear here.
          </p>
        </CardContent>
      </Card>

      <div className="grid gap-4 md:grid-cols-3">
        <Card className="border-slate-800 bg-slate-950/50">
          <CardContent className="p-4 text-xs text-slate-500 space-y-1">
            <p className="flex items-center gap-2"><Shield className="h-3 w-3" /> CSV/JSON export</p>
            <p>Timestamps and host tagging</p>
          </CardContent>
        </Card>
        <Card className="border-slate-800 bg-slate-950/50">
          <CardContent className="p-4 text-xs text-slate-500 space-y-1">
            <p className="flex items-center gap-2"><Skull className="h-3 w-3" /> Vulnerability timeline</p>
            <p>Patch verification tracking</p>
          </CardContent>
        </Card>
        <Card className="border-slate-800 bg-slate-950/50">
          <CardContent className="p-4 text-xs text-slate-500 space-y-1">
            <p className="flex items-center gap-2"><FileText className="h-3 w-3" /> Report generation</p>
            <p>Evidence for compliance</p>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
