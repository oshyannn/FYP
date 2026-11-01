import { useCallback, useEffect, useState } from "react";
import { api } from "../../../api";
import ThreatSubmissions from "./ThreatSubmissions";
import WhitelistRequests from "./WhitelistRequests";

interface Props {
  role: "employer" | "admin";
  onSessionEnd: () => void;
}

type Tab = "threats" | "whitelist";

// URL Approval. Administrators review threat URLs sent in by employers and whitelist requests;
// employers only review whitelist requests.
export default function UrlApproval({ role, onSessionEnd }: Props) {
  const admin = role === "admin";
  const [tab, setTab] = useState<Tab>(admin ? "threats" : "whitelist");
  const [pendingThreats, setPendingThreats] = useState(0);
  const [pendingWhitelist, setPendingWhitelist] = useState(0);

  // the numbers on the tabs, for both tabs even when only one is open
  const refresh = useCallback(async () => {
    const wl = await api.get("/api/staff/whitelist-requests?per_page=1");
    if (wl.status === 401) return onSessionEnd();
    if (wl.status === 200) setPendingWhitelist(wl.data.counts.pending as number);
    if (admin) {
      const th = await api.get("/api/staff/threat-submissions?per_page=1");
      if (th.status === 200) setPendingThreats(th.data.counts.pending as number);
    }
  }, [admin]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const tabs: { key: Tab; label: string; count: number }[] = [
    ...(admin ? [{ key: "threats" as Tab, label: "Threat URL Submissions", count: pendingThreats }] : []),
    { key: "whitelist", label: "Whitelist Requests", count: pendingWhitelist },
  ];

  return (
    <div className="max-w-5xl space-y-5">
      <div>
        <h2 className="text-xl font-bold text-slate-900">URL Approval</h2>
        <p className="text-slate-500 text-sm mt-0.5">Review and act on pending URL requests.</p>
      </div>

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
            {t.count > 0 && <span className="bg-amber-500 text-white text-[10px] font-bold px-1.5 py-0.5 rounded-full">{t.count}</span>}
          </button>
        ))}
      </div>

      {tab === "threats" && admin ? (
        <ThreatSubmissions onSessionEnd={onSessionEnd} onChanged={refresh} />
      ) : (
        <WhitelistRequests onSessionEnd={onSessionEnd} onChanged={refresh} />
      )}
    </div>
  );
}
