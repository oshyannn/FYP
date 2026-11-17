import { useCallback, useEffect, useState } from "react";
import { api } from "../../../api";
import type { StaffRole } from "../../../lib/admin";
import ThreatDetectionQueue from "./ThreatDetectionQueue";
import ThreatFormModal from "./ThreatFormModal";
import WhitelistRequests from "./WhitelistRequests";

interface Props {
  role: StaffRole;
  onSessionEnd: () => void;
}

type Tab = "threats" | "whitelist";

// URL Approval. Both Administrators and Employers review AI-detected threat URLs and global whitelist requests,
// and can manually add threat URLs directly to the Detection List.
export default function UrlApproval({ role, onSessionEnd }: Props) {
  const [tab, setTab] = useState<Tab>("threats");
  const [pendingThreats, setPendingThreats] = useState(0);
  const [pendingWhitelist, setPendingWhitelist] = useState(0);
  const [showAdd, setShowAdd] = useState(false);
  const [reloadKey, setReloadKey] = useState(0);
  const [notice, setNotice] = useState("");

  const refresh = useCallback(async () => {
    const [wl, th] = await Promise.all([
      api.get("/api/staff/whitelist-requests?per_page=1"),
      api.get("/api/threats?status=pending_review&per_page=1"),
    ]);
    if (wl.status === 401 || th.status === 401) return onSessionEnd();
    if (wl.status === 200) setPendingWhitelist((wl.data.counts?.pending as number) ?? 0);
    if (th.status === 200) setPendingThreats((th.data.stats?.pending as number) ?? 0);
  }, [onSessionEnd]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const tabs: { key: Tab; label: string; count: number }[] = [
    { key: "threats", label: "AI Threat Detections", count: pendingThreats },
    { key: "whitelist", label: "Global Whitelist Requests", count: pendingWhitelist },
  ];

  return (
    <div className="max-w-6xl space-y-5">
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h2 className="text-xl font-bold text-slate-900">URL Approval</h2>
          <p className="text-slate-500 text-sm mt-0.5">
            Review AI-detected threat URLs and global whitelist requests, or add threat URLs directly.
          </p>
        </div>
        <button
          type="button"
          onClick={() => {
            setNotice("");
            setShowAdd(true);
          }}
          className="shrink-0 bg-[#1e3a5f] text-white px-4 py-2.5 rounded-lg text-sm font-semibold hover:bg-[#162d4a] transition-colors flex items-center gap-2"
        >
          <span className="text-base leading-none">+</span> Add Threat URL
        </button>
      </div>

      {notice && (
        <div className="rounded-xl border border-green-200 bg-green-50 px-4 py-3 text-sm text-green-800" role="status">
          {notice}
        </div>
      )}

      <div className="flex border-b border-slate-200" role="tablist">
        {tabs.map((t) => (
          <button
            key={t.key}
            role="tab"
            aria-selected={tab === t.key}
            onClick={() => setTab(t.key)}
            className={`flex items-center gap-2 px-4 py-2.5 text-sm font-medium border-b-2 -mb-px transition-colors ${
              tab === t.key ? "border-[#1e3a5f] text-[#1e3a5f]" : "border-transparent text-slate-500 hover:text-slate-700"
            }`}
          >
            {t.label}
            {t.count > 0 && (
              <span className="bg-amber-500 text-white text-[10px] font-bold px-1.5 py-0.5 rounded-full">{t.count}</span>
            )}
          </button>
        ))}
      </div>

      {tab === "threats" ? (
        <ThreatDetectionQueue role={role} reloadKey={reloadKey} onSessionEnd={onSessionEnd} onChanged={refresh} />
      ) : (
        <WhitelistRequests role={role} onSessionEnd={onSessionEnd} onChanged={refresh} />
      )}

      {showAdd && (
        <ThreatFormModal
          role={role}
          onClose={() => setShowAdd(false)}
          onSessionEnd={onSessionEnd}
          onSaved={(msg) => {
            setShowAdd(false);
            setNotice(msg);
            setReloadKey((k) => k + 1);
            refresh();
          }}
        />
      )}
    </div>
  );
}
