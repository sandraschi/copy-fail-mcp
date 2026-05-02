import { cn } from "@/common/utils";

export function Badge({ className, variant = "default", ...props }: React.HTMLAttributes<HTMLSpanElement> & { variant?: "default" | "destructive" | "outline" | "secondary" }) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-semibold",
        variant === "default" && "border-transparent bg-primary text-primary-foreground",
        variant === "destructive" && "border-transparent bg-red-900/50 text-red-400",
        variant === "outline" && "border-slate-700 text-slate-400",
        variant === "secondary" && "border-transparent bg-slate-800 text-slate-300",
        className
      )}
      {...props}
    />
  );
}
