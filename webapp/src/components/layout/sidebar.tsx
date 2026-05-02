import { NavLink } from "react-router-dom";
import {
  RadioTower,
  History,
  HelpCircle,
  Skull,
  FlaskConical,
  LayoutDashboard,
  type LucideIcon,
} from "lucide-react";
import * as Tooltip from "@radix-ui/react-tooltip";

interface NavItem {
  label: string;
  icon: LucideIcon;
  path: string;
}

const navItems: NavItem[] = [
  { label: "Targets", icon: LayoutDashboard, path: "/" },
  { label: "Test Runner", icon: RadioTower, path: "/test-runner" },
  { label: "History", icon: History, path: "/history" },
  { label: "Help & Safety", icon: HelpCircle, path: "/help" },
  { label: "About CVE", icon: Skull, path: "/about" },
];

interface SidebarProps {
  collapsed: boolean;
}

export function Sidebar({ collapsed }: SidebarProps) {
  return (
    <aside
      className={`border-r border-slate-800 bg-slate-950/80 flex flex-col transition-all duration-300 ${
        collapsed ? "w-16" : "w-56"
      }`}
    >
      <div className="flex items-center h-14 border-b border-slate-800 px-4 gap-2">
        <FlaskConical className="h-4 w-4 text-red-500 shrink-0" />
        {!collapsed && (
          <span className="text-sm font-semibold text-white tracking-wide">
            Copy Fail MCP
          </span>
        )}
      </div>

      <nav className="flex-1 py-4 space-y-1 px-2">
        {navItems.map((item) =>
          collapsed ? (
            <Tooltip.Root key={item.path}>
              <Tooltip.Trigger asChild>
                <NavLink
                  to={item.path}
                  className={({ isActive }) =>
                    `flex items-center justify-center h-10 w-10 mx-auto rounded-md transition-colors ${
                      isActive
                        ? "bg-red-600/20 text-red-400"
                        : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/50"
                    }`
                  }
                >
                  <item.icon className="h-4 w-4" />
                </NavLink>
              </Tooltip.Trigger>
              <Tooltip.Portal>
                <Tooltip.Content
                  side="right"
                  className="bg-slate-900 text-slate-200 text-xs px-2 py-1 rounded border border-slate-700"
                >
                  {item.label}
                </Tooltip.Content>
              </Tooltip.Portal>
            </Tooltip.Root>
          ) : (
            <NavLink
              key={item.path}
              to={item.path}
              className={({ isActive }) =>
                `flex items-center gap-3 px-3 py-2 rounded-md text-sm transition-colors ${
                  isActive
                    ? "bg-red-600/20 text-red-400"
                    : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/50"
                }`
              }
            >
              <item.icon className="h-4 w-4 shrink-0" />
              <span>{item.label}</span>
            </NavLink>
          )
        )}
      </nav>
    </aside>
  );
}
