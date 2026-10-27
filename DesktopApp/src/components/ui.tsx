import type { ButtonHTMLAttributes, ReactNode } from "react";

export function Alert({ kind, children }: { kind: "error" | "info" | "success"; children: ReactNode }) {
  const styles = {
    error: "bg-red-50 border-red-200 text-red-700",
    info: "bg-blue-50 border-blue-200 text-blue-700",
    success: "bg-green-50 border-green-200 text-green-700",
  }[kind];
  return (
    <div role={kind === "error" ? "alert" : "status"} className={`mb-4 p-3 border rounded-lg text-xs leading-relaxed ${styles}`}>
      {children}
    </div>
  );
}

interface BtnProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  busy?: boolean;
  staff?: boolean;
}

export function PrimaryButton({ busy, staff, children, disabled, ...rest }: BtnProps) {
  return (
    <button
      {...rest}
      disabled={disabled || busy}
      className={`w-full text-white py-2.5 rounded-lg text-sm font-semibold transition-colors shadow-sm disabled:opacity-60 disabled:cursor-not-allowed ${
        staff ? "bg-[#14284a] hover:bg-[#0f1f3a]" : "bg-[#1e3a5f] hover:bg-[#162d4a]"
      }`}
    >
      {busy ? "Please wait…" : children}
    </button>
  );
}

export function SecondaryButton({ children, ...rest }: ButtonHTMLAttributes<HTMLButtonElement>) {
  return (
    <button
      {...rest}
      className="w-full border border-slate-300 bg-white text-slate-700 py-2.5 rounded-lg text-sm font-medium hover:bg-slate-50 transition-colors"
    >
      {children}
    </button>
  );
}

export function LinkButton({ children, ...rest }: ButtonHTMLAttributes<HTMLButtonElement>) {
  return (
    <button {...rest} type="button" className="text-[#1e3a5f] font-medium hover:underline">
      {children}
    </button>
  );
}
