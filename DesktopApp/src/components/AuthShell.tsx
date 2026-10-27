import type { ReactNode } from "react";
import Logo from "./Logo";

interface Props {
  portal: "user" | "staff";
  title: string;
  subtitle?: string;
  children: ReactNode;
  footer?: ReactNode;
}

export default function AuthShell({ portal, title, subtitle, children, footer }: Props) {
  const staff = portal === "staff";
  return (
    <div className="h-full overflow-y-auto">
      <div
        className={`min-h-full flex flex-col items-center justify-center p-4 bg-gradient-to-br ${
          staff ? "from-slate-100 to-slate-200" : "from-slate-50 to-blue-50"
        }`}
      >
        <div className="w-full max-w-md py-6">
          <div className="text-center mb-8">
            <Logo staff={staff} />
            <h1 className="text-2xl font-bold text-slate-900">{title}</h1>
            {subtitle && <p className="text-slate-500 text-sm mt-1">{subtitle}</p>}
          </div>
          <div className="bg-white rounded-2xl shadow-sm border border-slate-200 p-8">{children}</div>
          {footer && <div className="text-center text-sm text-slate-500 mt-5">{footer}</div>}
        </div>
      </div>
    </div>
  );
}
