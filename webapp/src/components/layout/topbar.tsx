import { FlaskConical, PanelLeftClose, PanelLeft } from "lucide-react";
import { PoisonBottle } from "@/common/poison-bottle";

interface TopbarProps {
  onToggle: () => void;
  collapsed: boolean;
}

export function Topbar({ onToggle, collapsed }: TopbarProps) {
  return (
    <header className="flex h-14 items-center justify-between border-b border-slate-800 bg-slate-950/50 px-4 backdrop-blur-xl">
      <div className="flex items-center gap-4">
        <button
          type="button"
          onClick={onToggle}
          className="flex h-7 w-7 items-center justify-center rounded-md text-slate-500 hover:text-slate-300 hover:bg-slate-800 transition-colors"
        >
          {collapsed ? (
            <PanelLeft className="h-4 w-4" />
          ) : (
            <PanelLeftClose className="h-4 w-4" />
          )}
        </button>
        <h1 className="text-sm font-medium text-slate-400">
          CVE-2026-31431 /{" "}
          <span className="text-slate-100 font-mono">Copy Fail</span>
        </h1>
      </div>

      <div className="flex items-center gap-2">
        <div className="flex items-center gap-2 rounded-full bg-red-900/20 px-3 py-1 text-xs text-red-400 border border-red-800/30">
          <PoisonBottle className="h-4 w-4" />
          <span className="hidden sm:inline">DANGER: Real LPE</span>
        </div>
      </div>
    </header>
  );
}
