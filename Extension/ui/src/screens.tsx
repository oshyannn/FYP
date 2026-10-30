import { useState } from "react";
import {
  AlertTriangleIcon, ArrowLeftIcon, CheckCircleIcon, ClockIcon, ExternalLinkIcon, GlobeIcon, PowerIcon,
  SearchIcon, ShieldCheckIcon, ShieldXIcon, SpinnerIcon,
} from "./icons";
import { clock, hostOf, stamp, statusLabel } from "./api";
import {
  ConfirmDialog, OutlineBtn, PrimaryBtn, ScoreBar, SectionLabel, StatusIcon, Toggle, UrlLine,
  statusBg, statusColor,
} from "./ui";
import type { RecentScan, Settings, Verdict } from "./types";

// ─── Pairing (replaces the old login page: the code comes from the desktop app) ──────────────
export function PairScreen({ notice, onSubmit }: { notice?: string; onSubmit: (code: string) => Promise<string | null> }) {
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const ready = code.replace(/[^A-Za-z0-9]/g, "").length >= 6;

  async function submit() {
    if (!ready || busy) return;
    setBusy(true);
    setError(null);
    const err = await onSubmit(code.trim());
    if (err) { setError(err); setBusy(false); }
  }

  return (
    <div className="p-5 fade-in flex-1 flex flex-col">
      <div className="flex flex-col items-center text-center mb-4">
        <div className="w-14 h-14 rounded-full bg-blue-50 border-2 border-blue-100 flex items-center justify-center mb-2">
          <ShieldCheckIcon size={24} className="text-[#0f2a4a]" />
        </div>
        <div className="text-[14px] font-bold text-gray-900">Connect to SafeBrowse</div>
        <div className="text-[11px] text-gray-500 mt-1 leading-relaxed">
          Link this extension to your SafeBrowse desktop app. No password needed here.
        </div>
      </div>

      <ol className="text-[11px] text-gray-600 space-y-1.5 mb-4 list-decimal pl-4 leading-relaxed">
        <li>Open the SafeBrowse desktop app and sign in.</li>
        <li>Click <b>Generate pairing code</b> under "Browser extension".</li>
        <li>Type the code below.</li>
      </ol>

      {notice && (
        <div className="bg-orange-50 border border-orange-200 text-orange-700 text-[11px] rounded-lg p-2.5 mb-3">{notice}</div>
      )}

      <label className="text-[9px] font-semibold text-gray-400 uppercase tracking-widest mb-1.5" htmlFor="code">Pairing code</label>
      <input
        id="code"
        autoFocus
        autoComplete="off"
        spellCheck={false}
        maxLength={12}
        placeholder="XXXX-XXXX"
        value={code}
        onChange={(e) => setCode(e.target.value.toUpperCase().replace(/[^A-Z0-9-]/g, ""))}
        onKeyDown={(e) => e.key === "Enter" && submit()}
        className="w-full px-3 py-2.5 text-[16px] text-center tracking-[0.25em] font-mono font-semibold border border-gray-300 rounded-lg bg-white focus:outline-none focus:ring-2 focus:ring-[#0f2a4a]/30 focus:border-[#0f2a4a] placeholder-gray-300 mb-3"
      />
      {error && <div className="bg-red-50 border border-red-200 text-red-700 text-[11px] rounded-lg p-2.5 mb-3">{error}</div>}
      <PrimaryBtn onClick={submit} disabled={!ready || busy} className="w-full py-2.5 text-[12px] flex items-center justify-center gap-2">
        {busy ? (<><SpinnerIcon size={14} className="text-white" />Connecting...</>) : "Connect"}
      </PrimaryBtn>
      <div className="text-[10px] text-gray-400 text-center mt-3 leading-relaxed">
        The code expires after a few minutes. Generate a new one if it stops working.
      </div>
    </div>
  );
}

// ─── Status screens ────────────────────────────────────────────────────────────
export function CheckingScreen({ url }: { url: string }) {
  return (
    <div className="flex flex-col items-center justify-center py-8 gap-3 fade-in">
      <div className="w-14 h-14 rounded-full border-2 border-blue-100 flex items-center justify-center">
        <SpinnerIcon size={22} className="text-[#0f2a4a]" />
      </div>
      <div className="text-center">
        <div className="text-[13px] font-semibold text-gray-800">Checking website...</div>
        <div className="text-[10px] text-gray-400 font-mono mt-0.5 truncate max-w-[240px]">{url}</div>
      </div>
      <div className="w-40 h-1 bg-gray-100 rounded-full overflow-hidden"><div className="h-full bg-[#0f2a4a]/60 rounded-full scan-bar" /></div>
      <div className="text-[9px] text-gray-400 tracking-widest uppercase">Analyzing URL...</div>
    </div>
  );
}

export function SafeScreen({ v, recordedAt, onViewDetails, onScanAgain, onActivity }: {
  v: Verdict; recordedAt?: number; onViewDetails: () => void; onScanAgain: () => void; onActivity: () => void;
}) {
  return (
    <div className="p-4 fade-in">
      <div className="mb-3">
        <SectionLabel>Current Website</SectionLabel>
        <div className="bg-gray-50 rounded-xl p-3 border border-gray-200 -mt-1.5">
          <div className="flex items-center gap-2 mb-2">
            <GlobeIcon size={13} className="text-gray-400" />
            <span className="text-[12px] font-mono font-medium text-gray-700 truncate">{hostOf(v.url)}</span>
            <span className="ml-auto text-[9px] text-gray-400 shrink-0">Auto-scanned</span>
          </div>
          <div className="flex items-center gap-2 mb-2.5">
            <CheckCircleIcon size={15} className="text-green-600" />
            <span className="text-[12px] font-bold text-green-600">SAFE</span>
          </div>
          <ScoreBar score={v.score} status="safe" />
          <div className="mt-2 text-[11px] text-gray-500">This website appears safe.</div>
        </div>
      </div>
      <div className="flex gap-2 mb-3">
        <OutlineBtn onClick={onViewDetails} className="flex-1"><ExternalLinkIcon size={11} />View Details</OutlineBtn>
        <PrimaryBtn onClick={onScanAgain} className="flex-1">Scan Again</PrimaryBtn>
      </div>
      {recordedAt && (
        <div className="bg-green-50 rounded-lg p-2.5 border border-green-200 flex items-center gap-2">
          <div className="w-1.5 h-1.5 rounded-full bg-green-500 pulse-dot" />
          <span className="text-[10px] text-green-700 font-medium">URL automatically recorded — {clock(recordedAt)}</span>
          <button onClick={onActivity} className="ml-auto text-[10px] text-green-600 font-semibold hover:underline underline-offset-2">View</button>
        </div>
      )}
    </div>
  );
}

export function SuspiciousScreen({ v, onBack, onViewDetails, onContinue }: {
  v: Verdict; onBack: () => void; onViewDetails: () => void; onContinue: () => void;
}) {
  const [confirm, setConfirm] = useState(false);
  return (
    <div className="p-4 fade-in relative">
      <div className="bg-orange-50 rounded-xl p-3 border border-orange-200 mb-3">
        <div className="flex items-start gap-2 mb-2">
          <AlertTriangleIcon size={18} className="text-orange-500 mt-0.5 shrink-0" />
          <div className="min-w-0">
            <div className="text-[13px] font-bold text-orange-700">Suspicious Website</div>
            <div className="text-[10px] font-mono text-gray-500 mt-0.5 truncate">{hostOf(v.url)}</div>
          </div>
        </div>
        <ScoreBar score={v.score} status="suspicious" />
        <div className="mt-2.5 text-[11px] text-gray-600 leading-relaxed">
          This website may contain security risks. Please review the details before continuing.
        </div>
      </div>
      <div className="flex flex-col gap-2">
        <div className="flex gap-2">
          <PrimaryBtn onClick={onBack} className="flex-1">Go Back</PrimaryBtn>
          <OutlineBtn onClick={onViewDetails} className="flex-1"><ExternalLinkIcon size={11} />View Details</OutlineBtn>
        </div>
        <button onClick={() => setConfirm(true)} className="w-full py-2 rounded-lg border border-orange-300 text-[11px] font-medium text-orange-600 hover:bg-orange-50 transition-colors">
          Continue Anyway
        </button>
      </div>
      {confirm && (
        <ConfirmDialog
          title="Are you sure you want to continue?"
          message="SafeBrowse cannot guarantee that this website is safe."
          onCancel={() => setConfirm(false)}
          onConfirm={() => { setConfirm(false); onContinue(); }}
          confirmClassName="bg-orange-500 hover:bg-orange-600 text-white"
        />
      )}
    </div>
  );
}

export function MaliciousScreen({ v, blockingEnabled, onWarningPage, onBack, onViewDetails, onContinue }: {
  v: Verdict; blockingEnabled: boolean; onWarningPage: boolean; onBack: () => void; onViewDetails: () => void; onContinue: () => void;
}) {
  const [confirm, setConfirm] = useState(false);
  const blocked = blockingEnabled && onWarningPage;
  return (
    <div className="p-4 fade-in relative">
      <div className="flex flex-col items-center mb-3">
        <div className="w-14 h-14 rounded-full bg-red-100 border-2 border-red-200 flex items-center justify-center mb-2">
          <ShieldXIcon size={24} className="text-red-600" />
        </div>
        <div className="text-[14px] font-bold text-red-700">{blocked ? "Website Blocked" : "Dangerous Website Detected"}</div>
        <div className="text-[10px] text-gray-500 text-center mt-1 leading-relaxed">
          {blocked
            ? "SafeBrowse blocked this website because it was detected as malicious."
            : blockingEnabled
              ? "This website was detected as malicious. Proceed with extreme caution."
              : "Website blocking is OFF. Proceed with extreme caution."}
        </div>
      </div>
      <div className="bg-red-50 rounded-xl p-3 border border-red-200 mb-3">
        <div className="flex items-center gap-2 mb-0.5">
          <GlobeIcon size={12} className="text-gray-400" />
          <span className="text-[11px] font-mono text-gray-700 truncate">{hostOf(v.url)}</span>
        </div>
        <ScoreBar score={v.score} status="malicious" />
        <div className="mt-2 flex items-center gap-1.5">
          <span className="text-[9px] uppercase tracking-widest text-gray-400">Threat:</span>
          <span className="text-[10px] font-bold text-red-600 bg-red-100 px-2 py-0.5 rounded-full">{v.adult ? "Adult content" : "Malicious"}</span>
        </div>
      </div>
      <div className="flex gap-2">
        <PrimaryBtn onClick={onBack} className="flex-1">Go Back to Safety</PrimaryBtn>
        <OutlineBtn onClick={onViewDetails} className="flex-1"><ExternalLinkIcon size={11} />View Details</OutlineBtn>
      </div>
      <button onClick={() => setConfirm(true)} className="w-full mt-2 py-2 rounded-lg border border-red-300 text-[11px] font-medium text-red-500 hover:bg-red-50 transition-colors">
        Continue to Website
      </button>
      {confirm && (
        <ConfirmDialog
          title="Continue to this potentially dangerous website?"
          message="SafeBrowse cannot protect you on this website. Malicious content may steal your information."
          onCancel={() => setConfirm(false)}
          onConfirm={() => { setConfirm(false); onContinue(); }}
        />
      )}
    </div>
  );
}

/** Used when the backend has no verdict ("not flagged, not confirmed safe"), the page cannot be scanned, or a scan failed. */
export function NoticeScreen({ icon, title, text, url, actions }: {
  icon: "info" | "power" | "error"; title: string; text: string; url?: string;
  actions?: { label: string; onClick: () => void; primary?: boolean }[];
}) {
  return (
    <div className="p-4 fade-in flex flex-col items-center text-center">
      <div className={`w-14 h-14 rounded-full border-2 flex items-center justify-center mb-3 ${icon === "error" ? "bg-orange-50 border-orange-200" : "bg-gray-100 border-gray-200"}`}>
        {icon === "power" ? <PowerIcon size={22} className="text-gray-400" />
          : icon === "error" ? <AlertTriangleIcon size={22} className="text-orange-500" />
          : <ShieldCheckIcon size={22} className="text-gray-400" />}
      </div>
      <div className="text-[13px] font-bold text-gray-700 mb-1">{title}</div>
      {url && <div className="text-[10px] font-mono text-gray-400 mb-1 max-w-[280px] truncate">{url}</div>}
      <div className="text-[11px] text-gray-400 mb-4 leading-relaxed">{text}</div>
      <div className="w-full flex flex-col gap-2">
        {actions?.map((a) => (
          a.primary
            ? <PrimaryBtn key={a.label} onClick={a.onClick} className="w-full py-2.5 text-[12px]">{a.label}</PrimaryBtn>
            : <OutlineBtn key={a.label} onClick={a.onClick} className="w-full">{a.label}</OutlineBtn>
        ))}
      </div>
    </div>
  );
}

// ─── Manual scan ────────────────────────────────────────────────────────────────
export function ManualScanScreen({ onScan }: { onScan: (url: string) => Promise<string | null> }) {
  const [url, setUrl] = useState("");
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function run() {
    if (!url.trim() || scanning) return;
    setScanning(true);
    setError(null);
    const err = await onScan(url.trim());
    if (err) { setError(err); setScanning(false); }
  }
  return (
    <div className="p-4 fade-in">
      <SectionLabel>Scan a URL</SectionLabel>
      <div className="relative mb-3">
        <div className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400"><SearchIcon size={13} /></div>
        <input
          type="text"
          placeholder="Paste URL here..."
          value={url}
          autoFocus
          onChange={(e) => setUrl(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && run()}
          className="w-full pl-8 pr-3 py-2.5 text-[12px] font-mono border border-gray-300 rounded-lg bg-white focus:outline-none focus:ring-2 focus:ring-[#0f2a4a]/30 focus:border-[#0f2a4a] placeholder-gray-400 transition"
        />
      </div>
      <PrimaryBtn onClick={run} disabled={!url.trim() || scanning} className="w-full py-2.5 text-[12px] flex items-center justify-center gap-2">
        {scanning ? (<><SpinnerIcon size={14} className="text-white" />Analyzing URL...</>) : "Scan URL"}
      </PrimaryBtn>
      {error && <div className="mt-3 bg-red-50 border border-red-200 text-red-700 text-[11px] rounded-lg p-2.5">{error}</div>}
      {scanning && (
        <div className="mt-3 bg-blue-50 rounded-lg p-2.5 border border-blue-200 text-center fade-in">
          <div className="text-[11px] text-blue-700 font-medium">Analyzing URL...</div>
          <div className="text-[10px] text-blue-500 mt-0.5">Checking against threat databases</div>
        </div>
      )}
    </div>
  );
}

export function ManualResultScreen({ v, onScanAnother, onViewDetails }: { v: Verdict; onScanAnother: () => void; onViewDetails: () => void }) {
  const msg = v.status === "safe" ? "This website appears safe."
    : v.status === "suspicious" ? "Be careful. This website may be unsafe."
    : v.status === "malicious" ? "Dangerous. Do not enter any personal information."
    : "No verdict yet: this site is not flagged, but it is not confirmed safe either.";
  return (
    <div className="p-4 fade-in">
      <SectionLabel>Scan Result</SectionLabel>
      <div className={`rounded-xl p-3 border mb-3 ${statusBg(v.status)}`}>
        <div className="flex items-center gap-2 mb-2">
          <GlobeIcon size={12} className="text-gray-400 shrink-0" />
          <span className="text-[11px] font-mono text-gray-700 truncate" title={v.url}>{v.url}</span>
        </div>
        <div className="flex items-center gap-2 mb-2">
          <StatusIcon s={v.status} size={14} />
          <span className={`text-[12px] font-bold ${statusColor(v.status)}`}>{statusLabel(v.status)}</span>
        </div>
        <ScoreBar score={v.score} status={v.status} />
        <div className="mt-2.5 text-[11px] text-gray-600 leading-relaxed">{msg}</div>
      </div>
      <div className="flex gap-2">
        <OutlineBtn onClick={onViewDetails} className="flex-1"><ExternalLinkIcon size={11} />View Details</OutlineBtn>
        <PrimaryBtn onClick={onScanAnother} className="flex-1">Scan Another</PrimaryBtn>
      </div>
    </div>
  );
}

// ─── Activity ─────────────────────────────────────────────────────────────────────
export function ActivityScreen({ current, recent, error, monitoring, onViewDetails, onOpenApp }: {
  current?: Verdict; recent: RecentScan[] | null; error?: string; monitoring: boolean;
  onViewDetails: (r: RecentScan) => void; onOpenApp: () => void;
}) {
  return (
    <div className="p-4 fade-in">
      <div className="flex items-center justify-between mb-3">
        <div className="text-[9px] font-semibold text-gray-400 uppercase tracking-widest">Real-Time Activity</div>
        <div className={`flex items-center gap-1.5 border px-2 py-1 rounded-full ${monitoring ? "bg-green-50 border-green-200" : "bg-gray-50 border-gray-200"}`}>
          <div className={`w-1.5 h-1.5 rounded-full ${monitoring ? "bg-green-500 pulse-dot" : "bg-gray-400"}`} />
          <span className={`text-[10px] font-semibold ${monitoring ? "text-green-700" : "text-gray-500"}`}>{monitoring ? "Monitoring" : "Paused"}</span>
        </div>
      </div>
      <div className="bg-gray-50 rounded-xl p-3 border border-gray-200 mb-3">
        <div className="text-[9px] text-gray-400 uppercase tracking-widest mb-1.5">Current URL</div>
        {current ? (
          <>
            <div className="flex items-center gap-1.5 mb-1.5">
              <GlobeIcon size={12} className="text-gray-400 shrink-0" />
              <span className="text-[11px] font-mono text-gray-700 truncate" title={current.url}>{current.url}</span>
            </div>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-1.5">
                <StatusIcon s={current.status} size={13} />
                <span className={`text-[11px] font-semibold ${statusColor(current.status)}`}>{statusLabel(current.status)}</span>
              </div>
              <div className="flex items-center gap-1 text-gray-400"><ClockIcon size={11} /><span className="text-[10px] font-mono">{clock(current.ts)}</span></div>
            </div>
          </>
        ) : (
          <div className="text-[11px] text-gray-400">No page checked yet.</div>
        )}
      </div>
      <SectionLabel>Recently Detected</SectionLabel>
      <div className="space-y-1.5 mb-3 -mt-1.5">
        {recent === null && !error && <div className="text-[11px] text-gray-400 py-2">Loading…</div>}
        {error && <div className="text-[11px] text-red-600 py-2">{error}</div>}
        {recent !== null && !error && recent.length === 0 && <div className="text-[11px] text-gray-400 py-2">Nothing recorded yet. Pages you visit are checked automatically.</div>}
        {(recent ?? []).slice(0, 3).map((r) => (
          <div key={r.id} className="flex items-center gap-2 bg-white rounded-lg px-3 py-2 border border-gray-200">
            <div className="shrink-0"><StatusIcon s={r.status} size={13} /></div>
            <div className="flex-1 min-w-0">
              <div className="text-[11px] font-mono text-gray-700 truncate" title={r.url}>{hostOf(r.url)}</div>
              <div className="flex items-center gap-1.5">
                <span className={`text-[9px] font-bold ${statusColor(r.status)}`}>{statusLabel(r.status)}</span>
                <span className="text-[10px] font-mono text-gray-400">{clock(r.ts)}</span>
              </div>
            </div>
            <button onClick={() => onViewDetails(r)} className="text-[10px] text-[#0f2a4a] font-semibold hover:underline underline-offset-2 flex items-center gap-0.5 shrink-0">
              <ExternalLinkIcon size={10} />View
            </button>
          </div>
        ))}
      </div>
      <OutlineBtn onClick={onOpenApp} className="w-full"><ExternalLinkIcon size={11} />See more in app</OutlineBtn>
    </div>
  );
}

// ─── Settings ──────────────────────────────────────────────────────────────────
export function SettingsScreen({ settings, email, onSave, onDisconnect }: {
  settings: Settings; email?: string | null; onSave: (s: Settings) => void; onDisconnect: () => void;
}) {
  const [draft, setDraft] = useState(settings);
  const [saved, setSaved] = useState(false);
  const [confirm, setConfirm] = useState(false);
  const toggle = (k: keyof Settings) => { setDraft((s) => ({ ...s, [k]: !s[k] })); setSaved(false); };
  const rows: { key: keyof Settings; label: string; hint?: (on: boolean) => string }[] = [
    { key: "realtime", label: "Real-Time URL Detection", hint: (on) => (on ? "Every page you open is checked first." : "Protection is off. Pages are not checked.") },
    { key: "autoscan", label: "Automatic Website Scanning", hint: (on) => (on ? "This popup scans the current page when opened." : "Use Scan Again to check the current page.") },
    { key: "blocking", label: "Website Blocking", hint: (on) => (on ? "SafeBrowse will block malicious websites." : "Detection only — no automatic blocking.") },
    { key: "notifications", label: "Security Notifications" },
  ];
  return (
    <div className="p-4 fade-in relative">
      <SectionLabel>Settings</SectionLabel>
      <div className="space-y-1 mb-4 -mt-1.5">
        {rows.map((r) => (
          <div key={r.key} className="flex items-center justify-between gap-3 py-2.5 border-b border-gray-100 last:border-0">
            <div>
              <div className="text-[12px] font-medium text-gray-800">{r.label}</div>
              {r.hint && <div className="text-[10px] text-gray-400 mt-0.5">{r.hint(draft[r.key])}</div>}
            </div>
            <Toggle checked={draft[r.key]} onChange={() => toggle(r.key)} />
          </div>
        ))}
      </div>
      <PrimaryBtn onClick={() => { onSave(draft); setSaved(true); }} className="w-full py-2.5 text-[12px] mb-3">
        {saved ? "Saved" : "Save Settings"}
      </PrimaryBtn>
      <div className={`border rounded-lg p-2.5 flex items-center gap-2 mb-4 ${settings.realtime ? "bg-green-50 border-green-200" : "bg-gray-50 border-gray-200"}`}>
        <div className={`w-1.5 h-1.5 rounded-full ${settings.realtime ? "bg-green-500 pulse-dot" : "bg-gray-400"}`} />
        <span className={`text-[11px] font-semibold ${settings.realtime ? "text-green-700" : "text-gray-500"}`}>
          SafeBrowse Protection Status: {settings.realtime ? "Active" : "Off"}
        </span>
      </div>

      <SectionLabel>Account</SectionLabel>
      <div className="bg-gray-50 border border-gray-200 rounded-xl p-3 -mt-1.5">
        <div className="text-[10px] text-gray-400 uppercase tracking-wide">Paired with desktop app as</div>
        <div className="text-[12px] font-medium text-gray-800 truncate mb-2">{email || "your account"}</div>
        <button onClick={() => setConfirm(true)} className="w-full py-2 rounded-lg border border-red-300 text-[11px] font-medium text-red-500 hover:bg-red-50 transition-colors">
          Disconnect this extension
        </button>
      </div>
      {confirm && (
        <ConfirmDialog
          title="Disconnect this extension?"
          message="Protection stops until you pair it again with a new code from the desktop app."
          confirmLabel="Disconnect"
          onCancel={() => setConfirm(false)}
          onConfirm={() => { setConfirm(false); onDisconnect(); }}
        />
      )}
    </div>
  );
}

// ─── Details ────────────────────────────────────────────────────────────────────
export function DetailsScreen({ v, onBack }: { v: Verdict; onBack: () => void }) {
  const rows = [
    { label: "URL", value: v.url },
    { label: "Risk Score", value: `${Math.round(v.score)} / 100`, hl: true },
    { label: "Verdict", value: v.adult ? "ADULT CONTENT" : statusLabel(v.status), hl: true },
    { label: "Detected by", value: v.source || "—" },
    { label: "Detection Time", value: stamp(v.ts) },
  ];
  return (
    <div className="p-4 fade-in">
      <SectionLabel>SafeBrowse Analysis</SectionLabel>
      <div className="bg-white rounded-xl border border-gray-200 overflow-hidden mb-3 -mt-1.5">
        <div className="bg-[#0f2a4a] px-3 py-2 flex items-center gap-2">
          <ShieldCheckIcon size={13} className="text-blue-200" />
          <span className="text-[11px] font-semibold text-white">Detailed URL Analysis</span>
        </div>
        <div className="p-3 space-y-2.5">
          {rows.map((r) => (
            <div key={r.label} className="flex items-start justify-between gap-3">
              <span className="text-[10px] text-gray-400 uppercase tracking-wide shrink-0">{r.label}</span>
              <span className={`text-[11px] font-mono font-semibold text-right break-all ${r.hl ? statusColor(v.status) : "text-gray-700"}`}>{r.value}</span>
            </div>
          ))}
          <div className="border-t border-gray-100 pt-2">
            <div className="text-[9px] text-gray-400 uppercase tracking-wide mb-1.5">Why this result</div>
            <div className="space-y-1">
              {v.reasons.length === 0 && <div className="text-[10px] text-gray-400">No detailed reasons were returned.</div>}
              {v.reasons.map((r, i) => (
                <div key={i} className={`text-[10px] font-mono px-2 py-1 rounded ${v.status === "malicious" ? "text-red-600 bg-red-50" : v.status === "suspicious" ? "text-orange-600 bg-orange-50" : "text-gray-600 bg-gray-50"}`}>
                  {r}
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
      <OutlineBtn onClick={onBack} className="w-full"><ArrowLeftIcon size={11} />Back to Extension</OutlineBtn>
    </div>
  );
}
