import type { ReactNode } from "react";
import {
  AlertTriangleIcon, ArrowLeftIcon, ActivityIcon, CheckCircleIcon, SearchIcon,
  SettingsIcon, ShieldCheckIcon, ShieldIcon, ShieldXIcon, GlobeIcon,
} from "./icons";
import type { Status } from "./types";

export type Screen =
  | "status" | "activity" | "manual_scan" | "manual_result" | "settings" | "details";

// ─── Status helpers (same colours as the Figma design; "unknown" is neutral grey) ─────────────
export const statusColor = (s: Status) =>
  s === "safe" ? "text-green-600" : s === "suspicious" ? "text-orange-500" : s === "malicious" ? "text-red-600" : "text-gray-500";
export const statusBg = (s: Status) =>
  s === "safe" ? "bg-green-50 border-green-200" : s === "suspicious" ? "bg-orange-50 border-orange-200"
    : s === "malicious" ? "bg-red-50 border-red-200" : "bg-gray-50 border-gray-200";
export const scoreBarColor = (s: Status) =>
  s === "safe" ? "bg-green-500" : s === "suspicious" ? "bg-orange-500" : s === "malicious" ? "bg-red-600" : "bg-gray-400";

export function StatusIcon({ s, size = 16 }: { s: Status; size?: number }) {
  if (s === "safe") return <CheckCircleIcon size={size} className="text-green-600" />;
  if (s === "suspicious") return <AlertTriangleIcon size={size} className="text-orange-500" />;
  if (s === "malicious") return <ShieldXIcon size={size} className="text-red-600" />;
  return <ShieldIcon size={size} className="text-gray-400" />;
}

// ─── Layout pieces ────────────────────────────────────────────────────────────
export function Header({ onSettings, onBack, title, showBack = false }: {
  onSettings?: () => void; onBack?: () => void; title?: string; showBack?: boolean;
}) {
  return (
    <div className="flex items-center justify-between px-4 py-3 bg-[#0f2a4a] text-white">
      <div className="flex items-center gap-2">
        {showBack && onBack && (
          <button onClick={onBack} className="mr-1 p-1 rounded hover:bg-white/10 transition-colors" aria-label="Back">
            <ArrowLeftIcon size={14} className="text-white/80" />
          </button>
        )}
        {!showBack && (
          <div className="flex items-center justify-center w-7 h-7 bg-blue-400/20 rounded-lg border border-blue-300/30">
            <ShieldCheckIcon size={15} className="text-blue-200" />
          </div>
        )}
        <div>
          {!showBack && <div className="text-[13px] font-bold tracking-wide leading-tight">SafeBrowse</div>}
          {showBack && <div className="text-[13px] font-semibold">{title}</div>}
          {!showBack && <div className="text-[9px] text-blue-300/80 font-mono tracking-wider">BROWSE SAFE. STAY PROTECTED.</div>}
        </div>
      </div>
      <div className="flex items-center gap-1">
        {onSettings && (
          <button onClick={onSettings} className="p-1.5 rounded-md hover:bg-white/10 transition-colors" aria-label="Settings">
            <SettingsIcon size={15} className="text-blue-200" />
          </button>
        )}
      </div>
    </div>
  );
}

export function NavBar({ screen, onNav }: { screen: Screen; onNav: (s: Screen) => void }) {
  const tabs: { id: Screen; label: string; icon: ReactNode }[] = [
    { id: "status", label: "Status", icon: <ShieldIcon size={14} /> },
    { id: "activity", label: "Activity", icon: <ActivityIcon size={14} /> },
    { id: "manual_scan", label: "Scan URL", icon: <SearchIcon size={14} /> },
  ];
  const active = screen === "manual_result" ? "manual_scan" : screen === "details" ? "status" : screen;
  return (
    <div className="flex border-t border-gray-200 bg-white">
      {tabs.map((t) => (
        <button
          key={t.id}
          onClick={() => onNav(t.id)}
          className={`flex-1 flex flex-col items-center gap-0.5 py-2 text-[10px] font-medium transition-colors ${
            active === t.id
              ? "text-[#0f2a4a] border-t-2 border-[#0f2a4a] -mt-px bg-white"
              : "text-gray-400 hover:text-gray-600 border-t-2 border-transparent"
          }`}
        >
          {t.icon}
          {t.label}
        </button>
      ))}
    </div>
  );
}

export function Footer({ on }: { on: boolean }) {
  return (
    <div className="px-4 py-2 bg-gray-50 border-t border-gray-200 flex items-center justify-between">
      <div className="flex items-center gap-1.5">
        <div className={`w-1.5 h-1.5 rounded-full ${on ? "bg-green-500 pulse-dot" : "bg-gray-400"}`} />
        <span className="text-[9px] text-gray-500 font-medium">Real-Time Protection: {on ? "ON" : "OFF"}</span>
      </div>
      <div className="flex items-center gap-1 text-gray-400">
        <ShieldCheckIcon size={10} className="text-[#0f2a4a]" />
        <span className="text-[9px] font-mono text-[#0f2a4a]">SafeBrowse v{chrome.runtime.getManifest().version}</span>
      </div>
    </div>
  );
}

export function Toggle({ checked, onChange }: { checked: boolean; onChange: () => void }) {
  return (
    <button
      role="switch"
      aria-checked={checked}
      onClick={onChange}
      className={`relative w-10 h-5 rounded-full transition-colors duration-200 ${checked ? "bg-[#0f2a4a]" : "bg-gray-300"}`}
    >
      <span className={`absolute top-0.5 left-0.5 w-4 h-4 bg-white rounded-full shadow transition-transform duration-200 ${checked ? "translate-x-5" : "translate-x-0"}`} />
    </button>
  );
}

export function ScoreBar({ score, status }: { score: number; status: Status }) {
  const pct = Math.max(0, Math.min(100, Math.round(score)));
  return (
    <div className="mt-1">
      <div className="flex items-center justify-between mb-1">
        <span className="text-[10px] text-gray-500 font-mono">Risk Score</span>
        <span className={`text-[11px] font-bold font-mono ${statusColor(status)}`}>{pct} / 100</span>
      </div>
      <div className="w-full h-1.5 bg-gray-200 rounded-full overflow-hidden">
        <div className={`h-full rounded-full transition-all duration-700 ${scoreBarColor(status)}`} style={{ width: `${pct}%` }} />
      </div>
    </div>
  );
}

export function ConfirmDialog({ title, message, onCancel, onConfirm, confirmLabel = "Continue",
  confirmClassName = "bg-red-600 hover:bg-red-700 text-white" }: {
  title: string; message: string; onCancel: () => void; onConfirm: () => void; confirmLabel?: string; confirmClassName?: string;
}) {
  return (
    <div className="absolute inset-0 bg-black/40 flex items-end z-50 fade-in">
      <div className="w-full bg-white rounded-t-2xl p-4 shadow-2xl">
        <div className="text-[13px] font-bold text-gray-900 mb-1">{title}</div>
        <div className="text-[11px] text-gray-500 mb-4 leading-relaxed">{message}</div>
        <div className="flex gap-2">
          <button onClick={onCancel} className="flex-1 py-2.5 rounded-lg border border-gray-300 text-[12px] font-medium text-gray-700 hover:bg-gray-50 transition-colors">Cancel</button>
          <button onClick={onConfirm} className={`flex-1 py-2.5 rounded-lg text-[12px] font-medium transition-colors ${confirmClassName}`}>{confirmLabel}</button>
        </div>
      </div>
    </div>
  );
}

export const SectionLabel = ({ children }: { children: ReactNode }) => (
  <div className="text-[9px] font-semibold text-gray-400 uppercase tracking-widest mb-3">{children}</div>
);

export const PrimaryBtn = ({ className = "", ...p }: React.ButtonHTMLAttributes<HTMLButtonElement>) => (
  <button {...p} className={`py-2 rounded-lg bg-[#0f2a4a] text-[11px] font-semibold text-white hover:bg-[#1a3a5c] transition-colors disabled:opacity-40 disabled:cursor-not-allowed ${className}`} />
);
export const OutlineBtn = ({ className = "", ...p }: React.ButtonHTMLAttributes<HTMLButtonElement>) => (
  <button {...p} className={`py-2 rounded-lg border border-[#0f2a4a] text-[11px] font-semibold text-[#0f2a4a] hover:bg-[#0f2a4a]/5 transition-colors flex items-center justify-center gap-1 ${className}`} />
);

export const UrlLine = ({ url, className = "" }: { url: string; className?: string }) => (
  <div className={`flex items-center gap-2 ${className}`}>
    <GlobeIcon size={13} className="text-gray-400 shrink-0" />
    <span className="text-[12px] font-mono font-medium text-gray-700 truncate" title={url}>{url}</span>
  </div>
);
