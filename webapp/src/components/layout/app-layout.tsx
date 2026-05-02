import { useState, useEffect } from "react";
import * as Tooltip from "@radix-ui/react-tooltip";
import { Sidebar } from "./sidebar";
import { Topbar } from "./topbar";

interface AppLayoutProps {
  children: React.ReactNode;
}

export function AppLayout({ children }: AppLayoutProps) {
  const [collapsed, setCollapsed] = useState(false);

  useEffect(() => {
    const stored = localStorage.getItem("cf-sidebar-collapsed");
    if (stored !== null) setCollapsed(stored === "true");
  }, []);

  const handleToggle = () => {
    const newState = !collapsed;
    setCollapsed(newState);
    localStorage.setItem("cf-sidebar-collapsed", String(newState));
  };

  return (
    <Tooltip.Provider>
      <div className="flex min-h-screen flex-col bg-slate-950 text-slate-50 font-sans selection:bg-red-500/30">
        <div className="flex flex-1 overflow-hidden">
          <Sidebar collapsed={collapsed} />
          <div className="flex flex-1 flex-col overflow-hidden">
            <Topbar onToggle={handleToggle} collapsed={collapsed} />
            <main className="flex-1 overflow-y-auto p-6 scroll-smooth">
              <div className="mx-auto max-w-7xl animate-in fade-in duration-500">
                {children}
              </div>
            </main>
          </div>
        </div>
      </div>
    </Tooltip.Provider>
  );
}
