import { cn } from "@/common/utils";
import { Slot } from "@radix-ui/react-slot";

export function Button({ className, variant = "default", size = "default", asChild = false, ...props }: React.ButtonHTMLAttributes<HTMLButtonElement> & { variant?: "default" | "destructive" | "outline" | "ghost"; size?: "default" | "sm" | "lg" | "icon"; asChild?: boolean }) {
  const Comp = asChild ? Slot : "button";
  return (
    <Comp
      className={cn(
        "inline-flex items-center justify-center rounded-md text-sm font-medium transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-slate-400 disabled:pointer-events-none disabled:opacity-50",
        variant === "default" && "bg-red-600 text-white hover:bg-red-700 shadow",
        variant === "destructive" && "bg-red-900/50 text-red-400 border border-red-800 hover:bg-red-900/70",
        variant === "outline" && "border border-slate-700 bg-transparent hover:bg-slate-800 text-slate-300",
        variant === "ghost" && "hover:bg-slate-800 text-slate-400",
        size === "default" && "h-9 px-4 py-2",
        size === "sm" && "h-8 px-3 text-xs",
        size === "lg" && "h-10 px-8",
        size === "icon" && "h-9 w-9",
        className
      )}
      {...props}
    />
  );
}
