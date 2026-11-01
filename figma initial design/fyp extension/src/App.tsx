import { useState, useEffect } from "react";

// ─── Types ────────────────────────────────────────────────────────────────────
type Status = "safe" | "suspicious" | "malicious";
type Screen =
  | "checking"
  | "safe"
  | "suspicious"
  | "malicious"
  | "manual_scan"
  | "manual_result"
  | "activity"
  | "history"
  | "settings"
  | "web_details"
  | "disabled"
  | "blocking_off";

interface HistoryRecord {
  time: string;
  url: string;
  status: Status;
  score: number;
}

const HISTORY: HistoryRecord[] = [
  { time: "10:35 AM", url: "suspicious-site.com", status: "suspicious", score: 67 },
  { time: "10:32 AM", url: "example.com", status: "safe", score: 5 },
  { time: "10:28 AM", url: "fake-login.com", status: "malicious", score: 96 },
  { time: "10:21 AM", url: "google.com", status: "safe", score: 2 },
  { time: "10:15 AM", url: "news-site.com", status: "suspicious", score: 55 },
];

// ─── Status helpers ────────────────────────────────────────────────────────────
function statusColor(s: Status) {
  if (s === "safe") return "text-green-600";
  if (s === "suspicious") return "text-orange-500";
  return "text-red-600";
}
function statusBg(s: Status) {
  if (s === "safe") return "bg-green-50 border-green-200";
  if (s === "suspicious") return "bg-orange-50 border-orange-200";
  return "bg-red-50 border-red-200";
}
function statusLabel(s: Status) {
  if (s === "safe") return "SAFE";
  if (s === "suspicious") return "SUSPICIOUS";
  return "MALICIOUS";
}
function statusIcon(s: Status, size = 16) {
  if (s === "safe") return <CheckCircleIcon size={size} className="text-green-600" />;
  if (s === "suspicious") return <AlertTriangleIcon size={size} className="text-orange-500" />;
  return <ShieldXIcon size={size} className="text-red-600" />;
}
function scoreBarColor(s: Status) {
  if (s === "safe") return "bg-green-500";
  if (s === "suspicious") return "bg-orange-500";
  return "bg-red-600";
}

// ─── Minimal icon components ──────────────────────────────────────────────────
function ShieldIcon({ size = 20, className = "" }: { size?: number; className?: string }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={className}>
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
    </svg>
  );
}
function ShieldCheckIcon({ size = 20, className = "" }: { size?: number; className?: string }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={className}>
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
      <polyline points="9 12 11 14 15 10" />
    </svg>
  );
}
function ShieldXIcon({ size = 20, className = "" }: { size?: number; className?: string }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={className}>
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
      <line x1="9.5" y1="9.5" x2="14.5" y2="14.5" />
      <line x1="14.5" y1="9.5" x2="9.5" y2="14.5" />
    </svg>
  );
}
function CheckCircleIcon({ size = 16, className = "" }: { size?: number; className?: string }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" className={className}>
      <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" />
      <polyline points="22 4 12 14.01 9 11.01" />
    </svg>
  );
}
function AlertTriangleIcon({ size = 16, className = "" }: { size?: number; className?: string }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={className}>
      <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
      <line x1="12" y1="9" x2="12" y2="13" />
      <line x1="12" y1="17" x2="12.01" y2="17" />
    </svg>
  );
}
function SettingsIcon({ size = 16, className = "" }: { size?: number; className?: string }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={className}>
      <circle cx="12" cy="12" r="3" />
      <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z" />
    </svg>
  );
}
function ClockIcon({ size = 14, className = "" }: { size?: number; className?: string }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={className}>
      <circle cx="12" cy="12" r="10" />
      <polyline points="12 6 12 12 16 14" />
    </svg>
  );
}
function GlobeIcon({ size = 14, className = "" }: { size?: number; className?: string }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={className}>
      <circle cx="12" cy="12" r="10" />
      <line x1="2" y1="12" x2="22" y2="12" />
      <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
    </svg>
  );
}
function ArrowLeftIcon({ size = 14, className = "" }: { size?: number; className?: string }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" className={className}>
      <line x1="19" y1="12" x2="5" y2="12" />
      <polyline points="12 19 5 12 12 5" />
    </svg>
  );
}
function ExternalLinkIcon({ size = 12, className = "" }: { size?: number; className?: string }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={className}>
      <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6" />
      <polyline points="15 3 21 3 21 9" />
      <line x1="10" y1="14" x2="21" y2="3" />
    </svg>
  );
}
function SearchIcon({ size = 14, className = "" }: { size?: number; className?: string }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={className}>
      <circle cx="11" cy="11" r="8" />
      <line x1="21" y1="21" x2="16.65" y2="16.65" />
    </svg>
  );
}
function ActivityIcon({ size = 14, className = "" }: { size?: number; className?: string }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={className}>
      <polyline points="22 12 18 12 15 21 9 3 6 12 2 12" />
    </svg>
  );
}
function PowerIcon({ size = 14, className = "" }: { size?: number; className?: string }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={className}>
      <path d="M18.36 6.64a9 9 0 1 1-12.73 0" />
      <line x1="12" y1="2" x2="12" y2="12" />
    </svg>
  );
}
function SpinnerIcon({ size = 18, className = "" }: { size?: number; className?: string }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" className={`spin-slow ${className}`}>
      <path d="M12 2a10 10 0 0 1 10 10" opacity="0.3" />
      <path d="M12 2a10 10 0 0 1 10 10" strokeDasharray="15 47" />
    </svg>
  );
}

// ─── Sub-components ────────────────────────────────────────────────────────────
function Header({
  onSettings,
  onBack,
  title,
  showBack = false,
}: {
  onSettings?: () => void;
  onBack?: () => void;
  title?: string;
  showBack?: boolean;
}) {
  return (
    <div className="flex items-center justify-between px-4 py-3 bg-[#0f2a4a] text-white">
      <div className="flex items-center gap-2">
        {showBack && onBack && (
          <button onClick={onBack} className="mr-1 p-1 rounded hover:bg-white/10 transition-colors">
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
          <button onClick={onSettings} className="p-1.5 rounded-md hover:bg-white/10 transition-colors">
            <SettingsIcon size={15} className="text-blue-200" />
          </button>
        )}
      </div>
    </div>
  );
}

function NavBar({ screen, onNav }: { screen: Screen; onNav: (s: Screen) => void }) {
  const tabs = [
    { id: "safe" as Screen, label: "Status", icon: <ShieldIcon size={14} /> },
    { id: "activity" as Screen, label: "Activity", icon: <ActivityIcon size={14} /> },
    { id: "manual_scan" as Screen, label: "Scan URL", icon: <SearchIcon size={14} /> },
    { id: "history" as Screen, label: "History", icon: <ClockIcon size={14} /> },
  ];
  const activeScreens: Record<string, string> = {
    safe: "safe", checking: "safe", suspicious: "safe", malicious: "safe",
    activity: "activity",
    manual_scan: "manual_scan", manual_result: "manual_scan",
    history: "history",
    settings: "settings",
    web_details: "safe",
    disabled: "safe",
    blocking_off: "safe",
  };
  const active = activeScreens[screen] || screen;
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

function Toggle({ checked, onChange }: { checked: boolean; onChange: () => void }) {
  return (
    <button
      onClick={onChange}
      className={`relative w-10 h-5 rounded-full transition-colors duration-200 ${checked ? "bg-[#0f2a4a]" : "bg-gray-300"}`}
    >
      <span
        className={`absolute top-0.5 left-0.5 w-4 h-4 bg-white rounded-full shadow transition-transform duration-200 ${checked ? "translate-x-5" : "translate-x-0"}`}
      />
    </button>
  );
}

function ScoreBar({ score, status }: { score: number; status: Status }) {
  return (
    <div className="mt-1">
      <div className="flex items-center justify-between mb-1">
        <span className="text-[10px] text-gray-500 font-mono">Risk Score</span>
        <span className={`text-[11px] font-bold font-mono ${statusColor(status)}`}>{score} / 100</span>
      </div>
      <div className="w-full h-1.5 bg-gray-200 rounded-full overflow-hidden">
        <div
          className={`h-full rounded-full transition-all duration-700 ${scoreBarColor(status)}`}
          style={{ width: `${score}%` }}
        />
      </div>
    </div>
  );
}

function ConfirmDialog({
  title,
  message,
  onCancel,
  onConfirm,
  confirmLabel = "Continue",
  confirmClassName = "bg-red-600 hover:bg-red-700 text-white",
}: {
  title: string;
  message: string;
  onCancel: () => void;
  onConfirm: () => void;
  confirmLabel?: string;
  confirmClassName?: string;
}) {
  return (
    <div className="absolute inset-0 bg-black/40 flex items-end z-50 fade-in">
      <div className="w-full bg-white rounded-t-2xl p-4 shadow-2xl">
        <div className="text-[13px] font-bold text-gray-900 mb-1">{title}</div>
        <div className="text-[11px] text-gray-500 mb-4 leading-relaxed">{message}</div>
        <div className="flex gap-2">
          <button
            onClick={onCancel}
            className="flex-1 py-2.5 rounded-lg border border-gray-300 text-[12px] font-medium text-gray-700 hover:bg-gray-50 transition-colors"
          >
            Cancel
          </button>
          <button
            onClick={onConfirm}
            className={`flex-1 py-2.5 rounded-lg text-[12px] font-medium transition-colors ${confirmClassName}`}
          >
            {confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}

// ─── Screens ──────────────────────────────────────────────────────────────────

function CheckingScreen({ url }: { url: string }) {
  return (
    <div className="flex flex-col items-center justify-center py-8 gap-3 fade-in">
      <div className="relative">
        <div className="w-14 h-14 rounded-full border-2 border-blue-100 flex items-center justify-center">
          <SpinnerIcon size={22} className="text-[#0f2a4a]" />
        </div>
      </div>
      <div className="text-center">
        <div className="text-[13px] font-semibold text-gray-800">Checking website...</div>
        <div className="text-[10px] text-gray-400 font-mono mt-0.5 truncate max-w-[200px]">{url}</div>
      </div>
      <div className="w-40 h-1 bg-gray-100 rounded-full overflow-hidden">
        <div className="h-full bg-[#0f2a4a]/60 rounded-full scan-bar" />
      </div>
      <div className="text-[9px] text-gray-400 tracking-widest uppercase">Analyzing URL...</div>
    </div>
  );
}

function SafeScreen({
  onViewDetails,
  onScanAgain,
  onActivity,
}: {
  onViewDetails: () => void;
  onScanAgain: () => void;
  onActivity: () => void;
}) {
  return (
    <div className="p-4 fade-in">
      {/* Current Website */}
      <div className="mb-3">
        <div className="text-[9px] font-semibold text-gray-400 uppercase tracking-widest mb-1.5">Current Website</div>
        <div className="bg-gray-50 rounded-xl p-3 border border-gray-200">
          <div className="flex items-center gap-2 mb-2">
            <GlobeIcon size={13} className="text-gray-400" />
            <span className="text-[12px] font-mono font-medium text-gray-700">example.com</span>
            <span className="ml-auto text-[9px] text-gray-400">Auto-scanned</span>
          </div>
          <div className="flex items-center gap-2 mb-2.5">
            <CheckCircleIcon size={15} className="text-green-600" />
            <span className="text-[12px] font-bold text-green-600">SAFE</span>
          </div>
          <ScoreBar score={4} status="safe" />
          <div className="mt-2 text-[11px] text-gray-500">This website appears safe.</div>
        </div>
      </div>
      {/* Buttons */}
      <div className="flex gap-2 mb-3">
        <button
          onClick={onViewDetails}
          className="flex-1 py-2 rounded-lg border border-[#0f2a4a] text-[11px] font-semibold text-[#0f2a4a] hover:bg-[#0f2a4a]/5 transition-colors flex items-center justify-center gap-1"
        >
          <ExternalLinkIcon size={11} />
          View Details
        </button>
        <button
          onClick={onScanAgain}
          className="flex-1 py-2 rounded-lg bg-[#0f2a4a] text-[11px] font-semibold text-white hover:bg-[#1a3a5c] transition-colors"
        >
          Scan Again
        </button>
      </div>
      {/* Recent auto-detection notice */}
      <div className="bg-green-50 rounded-lg p-2.5 border border-green-200 flex items-center gap-2">
        <div className="w-1.5 h-1.5 rounded-full bg-green-500 pulse-dot" />
        <span className="text-[10px] text-green-700 font-medium">URL automatically recorded — 10:32 AM</span>
        <button onClick={onActivity} className="ml-auto text-[10px] text-green-600 font-semibold underline-offset-2 hover:underline">
          View
        </button>
      </div>
    </div>
  );
}

function SuspiciousScreen({
  onBack,
  onViewDetails,
  onContinue,
}: {
  onBack: () => void;
  onViewDetails: () => void;
  onContinue: () => void;
}) {
  const [confirm, setConfirm] = useState(false);
  return (
    <div className="p-4 fade-in relative">
      <div className={`bg-orange-50 rounded-xl p-3 border border-orange-200 mb-3`}>
        <div className="flex items-start gap-2 mb-2">
          <AlertTriangleIcon size={18} className="text-orange-500 mt-0.5 shrink-0" />
          <div>
            <div className="text-[13px] font-bold text-orange-700">Suspicious Website</div>
            <div className="text-[10px] font-mono text-gray-500 mt-0.5">suspicious-example.com</div>
          </div>
        </div>
        <ScoreBar score={67} status="suspicious" />
        <div className="mt-2.5 text-[11px] text-gray-600 leading-relaxed">
          This website may contain security risks. Please review the details before continuing.
        </div>
      </div>
      <div className="flex flex-col gap-2">
        <div className="flex gap-2">
          <button
            onClick={onBack}
            className="flex-1 py-2 rounded-lg bg-[#0f2a4a] text-[11px] font-semibold text-white hover:bg-[#1a3a5c] transition-colors"
          >
            Go Back
          </button>
          <button
            onClick={onViewDetails}
            className="flex-1 py-2 rounded-lg border border-[#0f2a4a] text-[11px] font-semibold text-[#0f2a4a] hover:bg-[#0f2a4a]/5 transition-colors flex items-center justify-center gap-1"
          >
            <ExternalLinkIcon size={11} />
            View Details
          </button>
        </div>
        <button
          onClick={() => setConfirm(true)}
          className="w-full py-2 rounded-lg border border-orange-300 text-[11px] font-medium text-orange-600 hover:bg-orange-50 transition-colors"
        >
          Continue Anyway
        </button>
      </div>
      {confirm && (
        <ConfirmDialog
          title="Are you sure you want to continue?"
          message="SafeBrowse cannot guarantee that this website is safe."
          onCancel={() => setConfirm(false)}
          onConfirm={() => { setConfirm(false); onContinue(); }}
          confirmLabel="Continue"
          confirmClassName="bg-orange-500 hover:bg-orange-600 text-white"
        />
      )}
    </div>
  );
}

function MaliciousScreen({
  onBack,
  onViewDetails,
  blockingEnabled,
}: {
  onBack: () => void;
  onViewDetails: () => void;
  blockingEnabled: boolean;
}) {
  const [confirm, setConfirm] = useState(false);
  return (
    <div className="p-4 fade-in relative">
      <div className="flex flex-col items-center mb-3">
        <div className="w-14 h-14 rounded-full bg-red-100 border-2 border-red-200 flex items-center justify-center mb-2">
          <ShieldXIcon size={24} className="text-red-600" />
        </div>
        <div className="text-[14px] font-bold text-red-700">
          {blockingEnabled ? "Website Blocked" : "Dangerous Website Detected"}
        </div>
        <div className="text-[10px] text-gray-500 text-center mt-1 leading-relaxed">
          {blockingEnabled
            ? "SafeBrowse blocked this website because it was detected as malicious."
            : "Website blocking is OFF. Proceed with extreme caution."}
        </div>
      </div>
      <div className="bg-red-50 rounded-xl p-3 border border-red-200 mb-3">
        <div className="flex items-center gap-2 mb-0.5">
          <GlobeIcon size={12} className="text-gray-400" />
          <span className="text-[11px] font-mono text-gray-700">fake-login-example.com</span>
        </div>
        <ScoreBar score={96} status="malicious" />
        <div className="mt-2 flex items-center gap-1.5">
          <span className="text-[9px] uppercase tracking-widest text-gray-400">Threat:</span>
          <span className="text-[10px] font-bold text-red-600 bg-red-100 px-2 py-0.5 rounded-full">Phishing</span>
        </div>
      </div>
      <div className="flex gap-2">
        <button
          onClick={onBack}
          className="flex-1 py-2 rounded-lg bg-[#0f2a4a] text-[11px] font-semibold text-white hover:bg-[#1a3a5c] transition-colors"
        >
          Go Back to Safety
        </button>
        <button
          onClick={onViewDetails}
          className="flex-1 py-2 rounded-lg border border-[#0f2a4a] text-[11px] font-semibold text-[#0f2a4a] hover:bg-[#0f2a4a]/5 transition-colors flex items-center justify-center gap-1"
        >
          <ExternalLinkIcon size={11} />
          View Details
        </button>
      </div>
      <button
        onClick={() => setConfirm(true)}
        className="w-full mt-2 py-2 rounded-lg border border-red-300 text-[11px] font-medium text-red-500 hover:bg-red-50 transition-colors"
      >
        Continue to Website
      </button>
      {confirm && (
        <ConfirmDialog
          title="Continue to this potentially dangerous website?"
          message="SafeBrowse cannot protect you on this website. Malicious content may steal your information."
          onCancel={() => setConfirm(false)}
          onConfirm={() => setConfirm(false)}
          confirmLabel="Continue"
          confirmClassName="bg-red-600 hover:bg-red-700 text-white"
        />
      )}
    </div>
  );
}

function ManualScanScreen({ onResult }: { onResult: () => void }) {
  const [url, setUrl] = useState("");
  const [scanning, setScanning] = useState(false);
  const handleScan = () => {
    if (!url.trim()) return;
    setScanning(true);
    setTimeout(() => { setScanning(false); onResult(); }, 2000);
  };
  return (
    <div className="p-4 fade-in">
      <div className="text-[9px] font-semibold text-gray-400 uppercase tracking-widest mb-3">Scan a URL</div>
      <div className="relative mb-3">
        <div className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400">
          <SearchIcon size={13} />
        </div>
        <input
          type="text"
          placeholder="Paste URL here..."
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && handleScan()}
          className="w-full pl-8 pr-3 py-2.5 text-[12px] font-mono border border-gray-300 rounded-lg bg-white focus:outline-none focus:ring-2 focus:ring-[#0f2a4a]/30 focus:border-[#0f2a4a] placeholder-gray-400 transition"
        />
      </div>
      <button
        onClick={handleScan}
        disabled={!url.trim() || scanning}
        className="w-full py-2.5 rounded-lg bg-[#0f2a4a] text-[12px] font-semibold text-white hover:bg-[#1a3a5c] transition-colors disabled:opacity-40 disabled:cursor-not-allowed flex items-center justify-center gap-2"
      >
        {scanning ? (
          <>
            <SpinnerIcon size={14} className="text-white" />
            Analyzing URL...
          </>
        ) : (
          "Scan URL"
        )}
      </button>
      {scanning && (
        <div className="mt-3 bg-blue-50 rounded-lg p-2.5 border border-blue-200 text-center fade-in">
          <div className="text-[11px] text-blue-700 font-medium">Analyzing URL...</div>
          <div className="text-[10px] text-blue-500 mt-0.5">Checking against threat databases</div>
        </div>
      )}
    </div>
  );
}

function ManualResultScreen({
  onScanAnother,
  onViewDetails,
}: {
  onScanAnother: () => void;
  onViewDetails: () => void;
}) {
  return (
    <div className="p-4 fade-in">
      <div className="text-[9px] font-semibold text-gray-400 uppercase tracking-widest mb-3">Scan Result</div>
      <div className="bg-orange-50 rounded-xl p-3 border border-orange-200 mb-3">
        <div className="flex items-center gap-2 mb-2">
          <GlobeIcon size={12} className="text-gray-400" />
          <span className="text-[11px] font-mono text-gray-700">https://example-site.com</span>
        </div>
        <div className="flex items-center gap-2 mb-2">
          <AlertTriangleIcon size={14} className="text-orange-500" />
          <span className="text-[12px] font-bold text-orange-600">SUSPICIOUS</span>
        </div>
        <ScoreBar score={62} status="suspicious" />
        <div className="mt-2.5 text-[11px] text-gray-600 leading-relaxed">
          Be careful. This website may be unsafe.
        </div>
      </div>
      <div className="flex gap-2">
        <button
          onClick={onViewDetails}
          className="flex-1 py-2 rounded-lg border border-[#0f2a4a] text-[11px] font-semibold text-[#0f2a4a] hover:bg-[#0f2a4a]/5 transition-colors flex items-center justify-center gap-1"
        >
          <ExternalLinkIcon size={11} />
          View Details
        </button>
        <button
          onClick={onScanAnother}
          className="flex-1 py-2 rounded-lg bg-[#0f2a4a] text-[11px] font-semibold text-white hover:bg-[#1a3a5c] transition-colors"
        >
          Scan Another
        </button>
      </div>
    </div>
  );
}

function ActivityScreen({ onViewHistory }: { onViewHistory: () => void }) {
  const recent = HISTORY.slice(0, 3);
  return (
    <div className="p-4 fade-in">
      {/* Monitor status */}
      <div className="flex items-center justify-between mb-3">
        <div className="text-[9px] font-semibold text-gray-400 uppercase tracking-widest">Real-Time Activity</div>
        <div className="flex items-center gap-1.5 bg-green-50 border border-green-200 px-2 py-1 rounded-full">
          <div className="w-1.5 h-1.5 rounded-full bg-green-500 pulse-dot" />
          <span className="text-[10px] text-green-700 font-semibold">Monitoring</span>
        </div>
      </div>
      {/* Current URL */}
      <div className="bg-gray-50 rounded-xl p-3 border border-gray-200 mb-3">
        <div className="text-[9px] text-gray-400 uppercase tracking-widest mb-1.5">Current URL</div>
        <div className="flex items-center gap-1.5 mb-1.5">
          <GlobeIcon size={12} className="text-gray-400" />
          <span className="text-[11px] font-mono text-gray-700">https://example.com</span>
        </div>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-1.5">
            <CheckCircleIcon size={13} className="text-green-600" />
            <span className="text-[11px] font-semibold text-green-600">SAFE</span>
          </div>
          <div className="flex items-center gap-1 text-gray-400">
            <ClockIcon size={11} />
            <span className="text-[10px] font-mono">10:32 AM</span>
          </div>
        </div>
      </div>
      {/* Recent URLs */}
      <div className="text-[9px] font-semibold text-gray-400 uppercase tracking-widest mb-2">Recently Detected</div>
      <div className="space-y-1.5 mb-3">
        {recent.map((r, i) => (
          <div key={i} className="flex items-center gap-2 bg-white rounded-lg px-3 py-2 border border-gray-200">
            <div className="shrink-0">{statusIcon(r.status, 13)}</div>
            <span className="text-[11px] font-mono text-gray-700 flex-1 truncate">{r.url}</span>
            <span className={`text-[9px] font-bold ${statusColor(r.status)}`}>{statusLabel(r.status)}</span>
            <span className="text-[10px] font-mono text-gray-400 shrink-0">{r.time}</span>
          </div>
        ))}
      </div>
      <button
        onClick={onViewHistory}
        className="w-full py-2 rounded-lg border border-[#0f2a4a] text-[11px] font-semibold text-[#0f2a4a] hover:bg-[#0f2a4a]/5 transition-colors flex items-center justify-center gap-1"
      >
        <ExternalLinkIcon size={11} />
        View Full History
      </button>
    </div>
  );
}

function HistoryScreen({ onViewDetails }: { onViewDetails: () => void }) {
  return (
    <div className="p-4 fade-in">
      <div className="text-[9px] font-semibold text-gray-400 uppercase tracking-widest mb-3">Recent Activity</div>
      <div className="space-y-2 mb-3">
        {HISTORY.map((r, i) => (
          <div key={i} className={`rounded-xl p-3 border ${statusBg(r.status)}`}>
            <div className="flex items-center justify-between mb-1">
              <div className="flex items-center gap-1.5">
                {statusIcon(r.status, 13)}
                <span className={`text-[11px] font-bold ${statusColor(r.status)}`}>{statusLabel(r.status)}</span>
                <span className={`text-[10px] font-mono font-bold ${statusColor(r.status)}`}>{r.score}/100</span>
              </div>
              <div className="flex items-center gap-1 text-gray-400">
                <ClockIcon size={11} />
                <span className="text-[10px] font-mono">{r.time}</span>
              </div>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-mono text-gray-600">{r.url}</span>
              <button
                onClick={onViewDetails}
                className="text-[10px] text-[#0f2a4a] font-semibold hover:underline underline-offset-2 flex items-center gap-0.5"
              >
                <ExternalLinkIcon size={10} />
                View
              </button>
            </div>
          </div>
        ))}
      </div>
      <button
        onClick={onViewDetails}
        className="w-full py-2 rounded-lg bg-[#0f2a4a] text-[11px] font-semibold text-white hover:bg-[#1a3a5c] transition-colors flex items-center justify-center gap-1"
      >
        <ExternalLinkIcon size={11} />
        Open SafeBrowse History
      </button>
    </div>
  );
}

function SettingsScreen({ blocking, setBlocking }: { blocking: boolean; setBlocking: (v: boolean) => void }) {
  const [settings, setSettings] = useState({
    realtime: true,
    autoscan: true,
    blocking: blocking,
    notifications: true,
  });
  const toggle = (key: keyof typeof settings) => {
    if (key === "blocking") setBlocking(!settings.blocking);
    setSettings((s) => ({ ...s, [key]: !s[key] }));
  };
  const rows = [
    { key: "realtime" as const, label: "Real-Time URL Detection" },
    { key: "autoscan" as const, label: "Automatic Website Scanning" },
    { key: "blocking" as const, label: "Website Blocking" },
    { key: "notifications" as const, label: "Security Notifications" },
  ];
  return (
    <div className="p-4 fade-in">
      <div className="text-[9px] font-semibold text-gray-400 uppercase tracking-widest mb-3">Settings</div>
      <div className="space-y-1 mb-4">
        {rows.map((r) => (
          <div key={r.key} className="flex items-center justify-between py-2.5 border-b border-gray-100 last:border-0">
            <div>
              <div className="text-[12px] font-medium text-gray-800">{r.label}</div>
              {r.key === "blocking" && (
                <div className="text-[10px] text-gray-400 mt-0.5">
                  {settings.blocking
                    ? "SafeBrowse will block malicious websites."
                    : "Detection only — no automatic blocking."}
                </div>
              )}
            </div>
            <Toggle checked={settings[r.key]} onChange={() => toggle(r.key)} />
          </div>
        ))}
      </div>
      <button className="w-full py-2.5 rounded-lg bg-[#0f2a4a] text-[12px] font-semibold text-white hover:bg-[#1a3a5c] transition-colors mb-3">
        Save Settings
      </button>
      <div className="bg-green-50 border border-green-200 rounded-lg p-2.5 flex items-center gap-2">
        <div className="w-1.5 h-1.5 rounded-full bg-green-500 pulse-dot" />
        <span className="text-[11px] text-green-700 font-semibold">SafeBrowse Protection Status: Active</span>
      </div>
    </div>
  );
}

function WebDetailsScreen({ onBack }: { onBack: () => void }) {
  return (
    <div className="p-4 fade-in overflow-y-auto">
      <div className="text-[9px] font-semibold text-gray-400 uppercase tracking-widest mb-3">
        SafeBrowse Web System
      </div>
      {/* Simulated web panel */}
      <div className="bg-white rounded-xl border border-gray-200 overflow-hidden mb-3">
        <div className="bg-[#0f2a4a] px-3 py-2 flex items-center gap-2">
          <ShieldCheckIcon size={13} className="text-blue-200" />
          <span className="text-[11px] font-semibold text-white">Detailed URL Analysis</span>
        </div>
        <div className="p-3 space-y-2.5">
          {[
            { label: "URL", value: "fake-login-example.com" },
            { label: "Risk Score", value: "96 / 100", highlight: "malicious" as Status },
            { label: "Threat Type", value: "Phishing", highlight: "malicious" as Status },
            { label: "Detection Time", value: "10:28 AM, Aug 31 2026" },
          ].map((row) => (
            <div key={row.label} className="flex items-start justify-between gap-2">
              <span className="text-[10px] text-gray-400 uppercase tracking-wide shrink-0">{row.label}</span>
              <span className={`text-[11px] font-mono font-semibold text-right ${row.highlight ? statusColor(row.highlight) : "text-gray-700"}`}>
                {row.value}
              </span>
            </div>
          ))}
          <div className="border-t border-gray-100 pt-2">
            <div className="text-[9px] text-gray-400 uppercase tracking-wide mb-1.5">Security API Analysis</div>
            <div className="space-y-1">
              {["VirusTotal: MALICIOUS (12/94)", "Google Safe Browsing: DANGEROUS", "AI Risk Model: 96.2%"].map((v) => (
                <div key={v} className="text-[10px] font-mono text-red-600 bg-red-50 px-2 py-1 rounded">
                  {v}
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
      <button
        onClick={onBack}
        className="w-full py-2 rounded-lg border border-[#0f2a4a] text-[11px] font-semibold text-[#0f2a4a] hover:bg-[#0f2a4a]/5 transition-colors flex items-center justify-center gap-1"
      >
        <ArrowLeftIcon size={11} />
        Back to Extension
      </button>
    </div>
  );
}

function DisabledScreen({ onEnable }: { onEnable: () => void }) {
  return (
    <div className="p-4 fade-in flex flex-col items-center text-center">
      <div className="w-14 h-14 rounded-full bg-gray-100 border-2 border-gray-200 flex items-center justify-center mb-3">
        <PowerIcon size={22} className="text-gray-400" />
      </div>
      <div className="text-[13px] font-bold text-gray-700 mb-1">SafeBrowse is Disabled</div>
      <div className="text-[11px] text-gray-400 mb-4 leading-relaxed">
        Real-time protection is off. Your browsing is not being monitored.
      </div>
      <button
        onClick={onEnable}
        className="w-full py-2.5 rounded-lg bg-[#0f2a4a] text-[12px] font-semibold text-white hover:bg-[#1a3a5c] transition-colors"
      >
        Enable Protection
      </button>
    </div>
  );
}

// ─── State selector (demo scenario switcher) ──────────────────────────────────
const SCENARIOS: { label: string; screen: Screen; description: string }[] = [
  { label: "Safe", screen: "safe", description: "Safe website" },
  { label: "Checking", screen: "checking", description: "Checking website" },
  { label: "Suspicious", screen: "suspicious", description: "Suspicious website" },
  { label: "Malicious", screen: "malicious", description: "Malicious / blocked" },
  { label: "Scan", screen: "manual_scan", description: "Manual URL scan" },
  { label: "Activity", screen: "activity", description: "Real-time activity" },
  { label: "Disabled", screen: "disabled", description: "Extension disabled" },
];

// ─── Main App ─────────────────────────────────────────────────────────────────
export default function App() {
  const [screen, setScreen] = useState<Screen>("checking");
  const [blockingEnabled, setBlockingEnabled] = useState(true);

  // Auto-advance from checking → safe on first load
  useEffect(() => {
    if (screen === "checking") {
      const t = setTimeout(() => setScreen("safe"), 2200);
      return () => clearTimeout(t);
    }
  }, [screen]);

  function goBack() {
    setScreen("safe");
  }

  function renderScreen() {
    switch (screen) {
      case "checking":
        return <CheckingScreen url="https://example.com" />;
      case "safe":
        return (
          <SafeScreen
            onViewDetails={() => setScreen("web_details")}
            onScanAgain={() => { setScreen("checking"); }}
            onActivity={() => setScreen("activity")}
          />
        );
      case "suspicious":
        return (
          <SuspiciousScreen
            onBack={goBack}
            onViewDetails={() => setScreen("web_details")}
            onContinue={goBack}
          />
        );
      case "malicious":
        return (
          <MaliciousScreen
            onBack={goBack}
            onViewDetails={() => setScreen("web_details")}
            blockingEnabled={blockingEnabled}
          />
        );
      case "manual_scan":
        return <ManualScanScreen onResult={() => setScreen("manual_result")} />;
      case "manual_result":
        return (
          <ManualResultScreen
            onScanAnother={() => setScreen("manual_scan")}
            onViewDetails={() => setScreen("web_details")}
          />
        );
      case "activity":
        return <ActivityScreen onViewHistory={() => setScreen("history")} />;
      case "history":
        return <HistoryScreen onViewDetails={() => setScreen("web_details")} />;
      case "settings":
        return <SettingsScreen blocking={blockingEnabled} setBlocking={setBlockingEnabled} />;
      case "web_details":
        return <WebDetailsScreen onBack={() => setScreen("safe")} />;
      case "disabled":
        return <DisabledScreen onEnable={() => setScreen("checking")} />;
      default:
        return null;
    }
  }

  const showNav = !["checking", "web_details", "disabled"].includes(screen);
  const showSettingsBtn = !["settings", "web_details"].includes(screen);

  return (
    <div className="min-h-screen bg-slate-200 flex items-start justify-center pt-8 px-4 pb-8" style={{ fontFamily: "'Inter', sans-serif" }}>
      {/* Scenario selector */}
      <div className="fixed top-4 left-4 right-4 flex flex-wrap gap-1.5 justify-center z-40">
        {SCENARIOS.map((s) => (
          <button
            key={s.screen}
            onClick={() => setScreen(s.screen)}
            className={`px-2.5 py-1 rounded-full text-[10px] font-semibold border transition-all ${
              screen === s.screen || (screen === "manual_result" && s.screen === "manual_scan")
                ? "bg-[#0f2a4a] text-white border-[#0f2a4a] shadow-sm"
                : "bg-white text-gray-600 border-gray-300 hover:border-[#0f2a4a] hover:text-[#0f2a4a]"
            }`}
            title={s.description}
          >
            {s.label}
          </button>
        ))}
        <button
          onClick={() => setScreen("settings")}
          className={`px-2.5 py-1 rounded-full text-[10px] font-semibold border transition-all ${
            screen === "settings"
              ? "bg-[#0f2a4a] text-white border-[#0f2a4a] shadow-sm"
              : "bg-white text-gray-600 border-gray-300 hover:border-[#0f2a4a] hover:text-[#0f2a4a]"
          }`}
        >
          Settings
        </button>
      </div>

      {/* Chrome Extension Popup */}
      <div className="mt-12 w-[360px] shadow-2xl rounded-xl overflow-hidden border border-gray-300 bg-white flex flex-col" style={{ minHeight: 480 }}>
        {/* Chrome titlebar simulation */}
        <div className="bg-[#dee1e6] px-3 py-1.5 flex items-center gap-2 border-b border-gray-300/70">
          <div className="flex gap-1">
            <div className="w-2.5 h-2.5 rounded-full bg-[#ff5f57]" />
            <div className="w-2.5 h-2.5 rounded-full bg-[#febc2e]" />
            <div className="w-2.5 h-2.5 rounded-full bg-[#28c840]" />
          </div>
          <div className="flex-1 bg-white/80 rounded text-[9px] text-gray-500 font-mono px-2 py-0.5 text-center truncate">
            chrome-extension://safebrowse
          </div>
        </div>

        {/* Extension header */}
        <Header
          onSettings={showSettingsBtn ? () => setScreen("settings") : undefined}
          onBack={["settings", "web_details"].includes(screen) ? () => setScreen("safe") : undefined}
          showBack={["settings", "web_details"].includes(screen)}
          title={screen === "settings" ? "Settings" : screen === "web_details" ? "Web Analysis" : undefined}
        />

        {/* Screen content */}
        <div className="flex-1 overflow-y-auto">{renderScreen()}</div>

        {/* Footer status bar */}
        {showNav && (
          <div className="px-4 py-2 bg-gray-50 border-t border-gray-200 flex items-center justify-between">
            <div className="flex items-center gap-1.5">
              <div className="w-1.5 h-1.5 rounded-full bg-green-500 pulse-dot" />
              <span className="text-[9px] text-gray-500 font-medium">Real-Time Protection: ON</span>
            </div>
            <div className="flex items-center gap-1 text-gray-400">
              <ShieldCheckIcon size={10} className="text-[#0f2a4a]" />
              <span className="text-[9px] font-mono text-[#0f2a4a]">SafeBrowse v2.1</span>
            </div>
          </div>
        )}

        {/* Nav bar */}
        {showNav && <NavBar screen={screen} onNav={setScreen} />}
      </div>

      {/* Notification demos */}
      <div className="fixed bottom-4 right-4 flex flex-col gap-2 items-end">
        <div className="text-[9px] text-gray-400 font-semibold uppercase tracking-wider mb-1 text-right">Notifications</div>
        {[
          { icon: <CheckCircleIcon size={12} className="text-green-600" />, title: "Website checked", msg: "example.com is safe.", bg: "bg-white border-green-200" },
          { icon: <AlertTriangleIcon size={12} className="text-orange-500" />, title: "Suspicious detected", msg: "Review before continuing.", bg: "bg-orange-50 border-orange-200" },
          { icon: <ShieldXIcon size={12} className="text-red-600" />, title: "Malicious blocked", msg: "Access has been prevented.", bg: "bg-red-50 border-red-200" },
        ].map((n, i) => (
          <div key={i} className={`flex items-start gap-2 px-3 py-2 rounded-xl border shadow-sm w-52 ${n.bg}`}>
            <div className="mt-0.5 shrink-0">{n.icon}</div>
            <div>
              <div className="text-[10px] font-bold text-gray-800 flex items-center gap-1">
                <ShieldCheckIcon size={9} className="text-[#0f2a4a]" />
                SafeBrowse
              </div>
              <div className="text-[10px] font-semibold text-gray-700 leading-tight">{n.title}</div>
              <div className="text-[9px] text-gray-500">{n.msg}</div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
