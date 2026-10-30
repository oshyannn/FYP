import type { ReactNode } from "react";
import type { User } from "../../types";
import type { NavItem } from "./nav";

interface Props {
  user: User;
  roleLabel: string;
  nav: NavItem[];
  active: string;
  title: string;
  tone?: "user" | "staff";
  onNavigate: (id: string) => void;
  onLogout: () => void;
  children: ReactNode;
}

function initials(user: User): string {
  const name = (user.full_name ?? user.email).trim();
  const parts = name.split(/\s+/).filter(Boolean);
  return ((parts[0]?.[0] ?? "?") + (parts.length > 1 ? parts[parts.length - 1][0] : "")).toUpperCase();
}

export default function AppLayout({ user, roleLabel, nav, active, title, tone = "user", onNavigate, onLogout, children }: Props) {
  return (
    <div className="flex h-full bg-slate-50">
      <aside className={`w-60 shrink-0 ${tone === "staff" ? "bg-[#14284a]" : "bg-[#1e3a5f]"} flex flex-col`}>
        <div className="flex items-center gap-2.5 px-5 py-5 border-b border-white/10">
          <div className="w-8 h-8 bg-white/20 rounded-lg flex items-center justify-center text-white font-bold text-sm">SB</div>
          <div>
            <div className="text-white font-semibold text-sm leading-tight">SafeBrowse</div>
            <div className="text-blue-300 text-[10px]">{roleLabel}</div>
          </div>
        </div>
        <nav className="flex-1 overflow-y-auto py-4 px-3" aria-label="Main">
          {nav.map((item) =>
            item.ready ? (
              <button
                key={item.id}
                onClick={() => onNavigate(item.id)}
                aria-current={active === item.id ? "page" : undefined}
                className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium mb-0.5 transition-colors ${
                  active === item.id ? "bg-white/15 text-white" : "text-blue-200 hover:bg-white/10 hover:text-white"
                }`}
              >
                <span className="text-base w-5 text-center opacity-80">{item.icon}</span>
                {item.label}
              </button>
            ) : (
              <div
                key={item.id}
                aria-disabled="true"
                className="w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium mb-0.5 text-blue-200/40 cursor-not-allowed"
              >
                <span className="text-base w-5 text-center">{item.icon}</span>
                <span className="flex-1">{item.label}</span>
                <span className="text-[10px] border border-blue-200/30 rounded px-1">Soon</span>
              </div>
            ),
          )}
        </nav>
        <div className="p-3 border-t border-white/10">
          <button
            onClick={onLogout}
            className="w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium text-blue-200 hover:bg-white/10 hover:text-white transition-colors"
          >
            <span className="text-base w-5 text-center opacity-80">→</span>
            Logout
          </button>
        </div>
      </aside>

      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        <header className="bg-white border-b border-slate-200 px-6 py-3.5 flex items-center justify-between shrink-0">
          <h1 className="text-slate-800 font-semibold text-base">{title}</h1>
          <div
            className={`w-8 h-8 rounded-full ${tone === "staff" ? "bg-[#14284a]" : "bg-[#1e3a5f]"} text-white text-xs font-semibold flex items-center justify-center`}
            title={user.email}
          >
            {initials(user)}
          </div>
        </header>
        <main className="flex-1 overflow-y-auto p-6">{children}</main>
      </div>
    </div>
  );
}
