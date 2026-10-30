import { useCallback, useEffect, useState } from "react";
import { api, problem } from "../../api";
import Badge from "../../components/Badge";
import StatusBadge from "../../components/StatusBadge";
import { Alert } from "../../components/ui";
import { LEVEL_STYLE } from "../../lib/analysis";
import {
  THREAT_TYPE_OPTIONS, threatStatusLabel, threatStatusTone, threatTypeLabel, threatTypeTone,
} from "../../lib/threats";
import type { ThreatItem, ThreatStats, ThreatStatus } from "../../lib/threats";

interface Props {
  /** undefined = a normal user (read only, approved entries only) */
  staffRole?: "employer" | "admin";
  onSessionEnd: () => void;
}

type Decision = "approve" | "remove";
const PER_PAGE = 10;
const selectCls = "px-3.5 py-2 border border-slate-300 rounded-lg text-sm bg-white text-slate-700 focus:outline-none focus:border-[#1e3a5f]";

const TABS: { key: ThreatStatus; label: string }[] = [
  { key: "pending_review", label: "Pending review" },
  { key: "active", label: "Active list" },
  { key: "revoked", label: "Removed" },
];

export default function ThreatUrlList({ staffRole, onSessionEnd }: Props) {
  const staff = !!staffRole;
  const isAdmin = staffRole === "admin";
  const [tab, setTab] = useState<ThreatStatus>(staff ? "pending_review" : "active");
  const [search, setSearch] = useState("");
  const [q, setQ] = useState("");
  const [type, setType] = useState("");
  const [page, setPage] = useState(1);
  const [rows, setRows] = useState<ThreatItem[]>([]);
  const [total, setTotal] = useState(0);
  const [stats, setStats] = useState<ThreatStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [done, setDone] = useState("");
  const [view, setView] = useState<ThreatItem | null>(null);
  const [confirm, setConfirm] = useState<{ item: ThreatItem; decision: Decision } | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    const t = window.setTimeout(() => {
      setQ(search.trim());
      setPage(1);
    }, 300);
    return () => window.clearTimeout(t);
  }, [search]);

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    const qs = new URLSearchParams({ page: String(page), per_page: String(PER_PAGE) });
    if (staff) qs.set("status", tab);
    if (q) qs.set("search", q);
    if (type) qs.set("type", type);
    const res = await api.get(`/api/threats?${qs.toString()}`);
    setLoading(false);
    if (res.status === 401) return onSessionEnd();
    if (res.status !== 200) return setError(problem(res).message);
    setRows(res.data.threats as ThreatItem[]);
    setTotal(res.data.total as number);
    setStats(res.data.stats as ThreatStats);
  }, [q, type, page, tab, staff]);

  useEffect(() => {
    load();
  }, [load]);

  async function act() {
    if (!confirm || busy) return;
    setBusy(true);
    const res = await api.post(`/api/staff/threats/${confirm.item.id}/review`, { decision: confirm.decision });
    setBusy(false);
    if (res.status === 401) return onSessionEnd();
    const label = confirm.decision === "approve" ? "approved" : "removed";
    setConfirm(null);
    setView(null);
    if (res.status === 200) setDone(`Entry ${label}.`);
    else setError(problem(res).message);
    load();
  }

  /** what the signed-in staff member may do with a row */
  function actions(r: ThreatItem): { decision: Decision; label: string; danger?: boolean }[] {
    if (!staff) return [];
    if (r.status === "pending_review") return [{ decision: "approve", label: "Approve" }, { decision: "remove", label: "Reject", danger: true }];
    if (r.status === "active" && isAdmin) return [{ decision: "remove", label: "Remove", danger: true }];
    if (r.status === "revoked" && isAdmin) return [{ decision: "approve", label: "Reinstate" }];
    return [];
  }

  const cards: { label: string; value: number | undefined; color: string }[] = [
    { label: "Total Threats", value: stats?.total, color: "text-slate-800" },
    { label: "Phishing", value: stats?.phishing, color: "text-orange-600" },
    { label: "Malware", value: stats?.malware, color: "text-red-600" },
    { label: "Suspicious", value: stats?.suspicious, color: "text-amber-600" },
  ];
  if (staff) cards.push({ label: "Pending review", value: stats?.pending, color: "text-amber-600" });
  const pages = Math.max(1, Math.ceil(total / PER_PAGE));
  const cols = staff ? ["URL", "Threat Type", "Risk Score", "Detections", "Status", "Last Detected", "Action"] : ["URL", "Threat Type", "Risk Score", "Detections", "Last Detected", "Action"];

  return (
    <div className="max-w-6xl space-y-5">
      <div>
        <h2 className="text-xl font-bold text-slate-900">{staff ? "Threat URL Management" : "Threat URL List"}</h2>
        <p className="text-slate-500 text-sm mt-0.5">
          {staff ? "Review detected URLs and manage the Global Threat List." : "Websites that have been identified as security threats."}
        </p>
      </div>

      {error && <Alert kind="error">{error}</Alert>}
      {done && <Alert kind="success">{done}</Alert>}

      <div className={`grid gap-4 ${staff ? "grid-cols-5" : "grid-cols-4"}`}>
        {cards.map((c) => (
          <div key={c.label} className="bg-white rounded-xl border border-slate-200 p-4 text-center">
            <div className={`text-2xl font-bold ${c.color}`}>{c.value ?? "–"}</div>
            <div className="text-slate-500 text-xs mt-1">{c.label}</div>
          </div>
        ))}
      </div>

      {staff && (
        <div className="flex gap-1 border-b border-slate-200" role="tablist">
          {TABS.map((t) => (
            <button
              key={t.key}
              role="tab"
              aria-selected={tab === t.key}
              onClick={() => { setTab(t.key); setPage(1); setDone(""); }}
              className={`px-4 py-2.5 text-sm font-medium border-b-2 -mb-px flex items-center gap-2 ${
                tab === t.key ? "border-[#1e3a5f] text-[#1e3a5f]" : "border-transparent text-slate-500 hover:text-slate-700"
              }`}
            >
              {t.label}
              {t.key === "pending_review" && !!stats?.pending && (
                <span className="bg-amber-500 text-white text-[10px] font-bold px-1.5 py-0.5 rounded-full">{stats.pending}</span>
              )}
            </button>
          ))}
        </div>
      )}

      <div className="flex flex-wrap gap-3">
        <input
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          maxLength={200}
          aria-label="Search threat URL"
          placeholder="Search threat URL..."
          className="flex-1 min-w-36 px-3.5 py-2 border border-slate-300 rounded-lg text-sm placeholder-slate-400 bg-white focus:outline-none focus:border-[#1e3a5f] focus:ring-2 focus:ring-[#1e3a5f]/10"
        />
        <select value={type} onChange={(e) => { setType(e.target.value); setPage(1); }} aria-label="Filter by threat type" className={selectCls}>
          <option value="">All Types</option>
          {THREAT_TYPE_OPTIONS.map(([v, l]) => (
            <option key={v} value={v}>{l}</option>
          ))}
        </select>
      </div>

      <div className="bg-white rounded-xl border border-slate-200 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="text-xs text-slate-500 bg-slate-50 border-b border-slate-200">
                {cols.map((h) => (
                  <th key={h} className="text-left px-5 py-3 font-medium">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {rows.map((r) => (
                <tr key={r.id} className="hover:bg-slate-50 transition-colors">
                  <td className="px-5 py-3.5 text-sm font-mono text-slate-700 max-w-xs truncate" title={r.url}>{r.url}</td>
                  <td className="px-5 py-3.5"><Badge tone={threatTypeTone(r.threat_type)}>{threatTypeLabel(r.threat_type)}</Badge></td>
                  <td className="px-5 py-3.5 text-sm font-semibold"><span className={LEVEL_STYLE[r.risk_level].text}>{Math.round(r.risk_score)}/100</span></td>
                  <td className="px-5 py-3.5 text-sm text-slate-600">{r.detection_count}</td>
                  {staff && <td className="px-5 py-3.5"><Badge tone={threatStatusTone(r.status)}>{threatStatusLabel(r.status)}</Badge></td>}
                  <td className="px-5 py-3.5 text-sm text-slate-500 whitespace-nowrap">{new Date(r.last_verified_at).toLocaleDateString()}</td>
                  <td className="px-5 py-3.5">
                    <div className="flex items-center gap-3">
                      <button onClick={() => setView(r)} className="text-[#1e3a5f] text-sm font-medium hover:underline">View</button>
                      {actions(r).map((a) => (
                        <button
                          key={a.label}
                          onClick={() => { setDone(""); setConfirm({ item: r, decision: a.decision }); }}
                          className={`text-sm font-medium hover:underline ${a.danger ? "text-red-500" : "text-green-700"}`}
                        >
                          {a.label}
                        </button>
                      ))}
                    </div>
                  </td>
                </tr>
              ))}
              {rows.length === 0 && (
                <tr>
                  <td colSpan={cols.length} className="px-5 py-10 text-center text-slate-400 text-sm">
                    {loading ? "Loading…" : "No threat URLs found."}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
        {total > PER_PAGE && (
          <div className="px-5 py-3.5 border-t border-slate-100 flex items-center justify-between text-sm text-slate-600">
            <span>Showing {(page - 1) * PER_PAGE + 1}–{Math.min(page * PER_PAGE, total)} of {total}</span>
            <div className="flex gap-1">
              {Array.from({ length: pages }, (_, i) => i + 1).map((p) => (
                <button
                  key={p}
                  onClick={() => setPage(p)}
                  aria-current={p === page ? "page" : undefined}
                  className={`w-8 h-8 rounded-lg text-sm font-medium ${p === page ? "bg-[#1e3a5f] text-white" : "hover:bg-slate-100 text-slate-600"}`}
                >
                  {p}
                </button>
              ))}
            </div>
          </div>
        )}
      </div>

      {view && (
        <div className="fixed inset-0 z-50 bg-black/40 flex items-center justify-center p-4" role="dialog" aria-modal="true" aria-label="Threat URL details">
          <div className="bg-white rounded-2xl shadow-xl w-full max-w-md">
            <div className="flex items-center justify-between px-6 py-5 border-b border-slate-100">
              <h3 className="font-semibold text-slate-900">Threat URL Details</h3>
              <button onClick={() => setView(null)} aria-label="Close" className="text-slate-400 hover:text-slate-600 text-2xl leading-none">×</button>
            </div>
            <div className="px-6 py-5 divide-y divide-slate-100 text-sm">
              {([
                ["URL", <span className="font-mono text-xs text-slate-800 break-all">{view.url}</span>],
                ["Threat Type", <Badge tone={threatTypeTone(view.threat_type)}>{threatTypeLabel(view.threat_type)}</Badge>],
                ["Risk Level", <StatusBadge level={view.risk_level} />],
                ["Risk Score", <span className={`font-bold ${LEVEL_STYLE[view.risk_level].text}`}>{Math.round(view.risk_score)}/100</span>],
                ["Status", <Badge tone={threatStatusTone(view.status)}>{threatStatusLabel(view.status)}</Badge>],
                ["Times detected", <span className="text-slate-700">{view.detection_count}</span>],
                ["First detected", <span className="text-slate-700">{new Date(view.created_at).toLocaleString()}</span>],
                ["Last detected", <span className="text-slate-700">{new Date(view.last_verified_at).toLocaleString()}</span>],
              ] as [string, React.ReactNode][]).map(([l, v]) => (
                <div key={l} className="flex items-center justify-between py-3 gap-4">
                  <span className="text-slate-500 shrink-0">{l}</span>
                  <div className="text-right min-w-0">{v}</div>
                </div>
              ))}
            </div>
            <div className="px-6 py-4 border-t border-slate-100 flex gap-3">
              <button onClick={() => setView(null)} className="flex-1 border border-slate-300 text-slate-700 py-2.5 rounded-lg text-sm font-medium hover:bg-slate-50">Close</button>
              {actions(view).map((a) => (
                <button
                  key={a.label}
                  onClick={() => setConfirm({ item: view, decision: a.decision })}
                  className={`flex-1 py-2.5 rounded-lg text-sm font-medium ${a.danger ? "border border-red-300 text-red-600 hover:bg-red-50" : "bg-green-600 text-white hover:bg-green-700"}`}
                >
                  {a.label}
                </button>
              ))}
            </div>
          </div>
        </div>
      )}

      {confirm && (
        <div className="fixed inset-0 z-[60] bg-black/40 flex items-center justify-center p-4" role="dialog" aria-modal="true" aria-labelledby="th-confirm">
          <div className="bg-white rounded-2xl p-6 max-w-sm w-full shadow-xl">
            <h3 id="th-confirm" className="font-semibold text-slate-900 mb-2">
              {confirm.decision === "approve" ? "Add to the Threat List?" : "Remove from the Threat List?"}
            </h3>
            <p className="text-slate-500 text-sm mb-1 font-mono break-all">{confirm.item.url}</p>
            <p className="text-slate-500 text-sm mb-5">
              {confirm.decision === "approve"
                ? "This URL will be shown to all users as a confirmed threat."
                : "This URL will no longer be shown in the Global Threat List."}
            </p>
            <div className="flex gap-3">
              <button onClick={() => setConfirm(null)} className="flex-1 border border-slate-300 text-slate-700 py-2.5 rounded-lg text-sm font-medium">Cancel</button>
              <button
                onClick={act}
                disabled={busy}
                className={`flex-1 py-2.5 rounded-lg text-sm font-medium text-white disabled:opacity-60 ${confirm.decision === "approve" ? "bg-green-600 hover:bg-green-700" : "bg-red-600 hover:bg-red-700"}`}
              >
                {busy ? "Please wait…" : "Confirm"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
