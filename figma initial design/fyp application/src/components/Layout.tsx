import { ReactNode, useState } from "react";
import type { AppState, Page, Role } from "../types";

interface NavItem {
  id: Page;
  label: string;
  icon: string;
}

const userNav: NavItem[] = [
  { id: "user-dashboard", label: "Dashboard", icon: "⊞" },
  { id: "url-scanner", label: "URL Scanner", icon: "⌕" },
  { id: "detection-history", label: "Detection History", icon: "☰" },
  { id: "threat-url-list", label: "Threat URL List", icon: "⚠" },
  { id: "whitelist", label: "Whitelist", icon: "✓" },
  { id: "browser-activity", label: "Browser Activity", icon: "◉" },
  { id: "feedback", label: "Feedback", icon: "✉" },
  { id: "profile", label: "Profile", icon: "◯" },
  { id: "settings", label: "Settings", icon: "⚙" },
];

const employerNav: NavItem[] = [
  { id: "employer-dashboard", label: "Dashboard", icon: "⊞" },
  { id: "url-approval", label: "URL Approval", icon: "✓" },
  { id: "threat-url-list", label: "Threat URL List", icon: "⚠" },
  { id: "employer-feedback", label: "User Feedback", icon: "✉" },
  { id: "profile", label: "Profile", icon: "◯" },
];

const adminNav: NavItem[] = [
  { id: "admin-dashboard", label: "Dashboard", icon: "⊞" },
  { id: "user-management", label: "User Management", icon: "◯◯" },
  { id: "employer-verification", label: "Employer Verification", icon: "✓" },
  { id: "admin-url-approval", label: "URL Approval", icon: "⌕" },
  { id: "admin-threat-urls", label: "Threat URLs", icon: "⚠" },
  { id: "whitelist", label: "Whitelist", icon: "☰" },
  { id: "employer-feedback", label: "Feedback", icon: "✉" },
  { id: "activity-logs", label: "Activity Logs", icon: "📋" },
  { id: "admin-settings", label: "Settings", icon: "⚙" },
];

interface Props {
  state: AppState;
  navigate: (page: Page) => void;
  children: ReactNode;
  title: string;
}

export default function Layout({ state, navigate, children, title }: Props) {
  const [mobileOpen, setMobileOpen] = useState(false);

  const navItems =
    state.role === "admin"
      ? adminNav
      : state.role === "employer"
        ? employerNav
        : userNav;

  const homePage: Page =
    state.role === "admin"
      ? "admin-dashboard"
      : state.role === "employer"
        ? "employer-dashboard"
        : "user-dashboard";

  const roleLabel =
    state.role === "admin" ? "Admin" : state.role === "employer" ? "Employer" : "User";

  return (
    <div className="flex h-full bg-slate-50">
      {/* Sidebar */}
      <aside
        className={`fixed inset-y-0 left-0 z-30 w-60 bg-[#1e3a5f] flex flex-col transition-transform duration-300 ${mobileOpen ? "translate-x-0" : "-translate-x-full"} lg:relative lg:translate-x-0`}
      >
        {/* Logo */}
        <div className="flex items-center gap-2.5 px-5 py-5 border-b border-white/10">
          <div className="w-8 h-8 bg-white/20 rounded-lg flex items-center justify-center text-white font-bold text-sm">
            SB
          </div>
          <div>
            <div className="text-white font-semibold text-sm leading-tight">SafeBrowse</div>
            <div className="text-blue-300 text-[10px]">{roleLabel}</div>
          </div>
        </div>

        {/* Nav */}
        <nav className="flex-1 overflow-y-auto py-4 px-3">
          {navItems.map((item) => {
            const active = state.page === item.id;
            return (
              <button
                key={item.id}
                onClick={() => { navigate(item.id); setMobileOpen(false); }}
                className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium mb-0.5 transition-colors ${active ? "bg-white/15 text-white" : "text-blue-200 hover:bg-white/10 hover:text-white"}`}
              >
                <span className="text-base w-5 text-center opacity-80">{item.icon}</span>
                {item.label}
              </button>
            );
          })}
        </nav>

        {/* Logout */}
        <div className="p-3 border-t border-white/10">
          <button
            onClick={() => navigate("login")}
            className="w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium text-blue-200 hover:bg-white/10 hover:text-white transition-colors"
          >
            <span className="text-base w-5 text-center opacity-80">→</span>
            Logout
          </button>
        </div>
      </aside>

      {/* Mobile overlay */}
      {mobileOpen && (
        <div
          className="fixed inset-0 z-20 bg-black/40 lg:hidden"
          onClick={() => setMobileOpen(false)}
        />
      )}

      {/* Main content */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {/* Top nav */}
        <header className="bg-white border-b border-slate-200 px-6 py-3.5 flex items-center justify-between shrink-0">
          <div className="flex items-center gap-3">
            <button
              onClick={() => setMobileOpen(!mobileOpen)}
              className="lg:hidden text-slate-500 hover:text-slate-700"
            >
              ☰
            </button>
            <h1 className="text-slate-800 font-semibold text-base">{title}</h1>
          </div>
          <div className="flex items-center gap-3">
            <button className="relative text-slate-500 hover:text-slate-700 text-xl p-1">
              🔔
              <span className="absolute top-0.5 right-0.5 w-2 h-2 bg-red-500 rounded-full"></span>
            </button>
            <button
              onClick={() => navigate("profile")}
              className="flex items-center gap-2 hover:opacity-80 transition-opacity"
            >
              <div className="w-8 h-8 rounded-full bg-[#1e3a5f] text-white text-xs font-semibold flex items-center justify-center">
                {state.role === "admin" ? "AD" : state.role === "employer" ? "EM" : "JT"}
              </div>
            </button>
          </div>
        </header>

        {/* Page content */}
        <main className="flex-1 overflow-y-auto p-6">{children}</main>
      </div>
    </div>
  );
}
