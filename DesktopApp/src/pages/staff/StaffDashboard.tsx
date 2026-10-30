import { useEffect, useState } from "react";
import { api, problem } from "../../api";
import Badge from "../../components/Badge";
import StatusBadge from "../../components/StatusBadge";
import { Alert } from "../../components/ui";
import { activityText, percent } from "../../lib/dashboard";
import type { StaffSummary } from "../../lib/dashboard";
import { threatTypeLabel, threatTypeTone } from "../../lib/threats";

interface Props {
  role: "employer" | "admin";
  name: string;
  onNavigate: (id: string) => void;
  onSessionEnd: () => void;
}

const BARS = [
  { key: "safe", label: "Safe", color: "bg-green-500" },
  { key: "suspicious", label: "Suspicious", color: "bg-amber-500" },
  { key: "malicious", label: "Malicious", color: "bg-red-500" },
  { key: "unknown", label: "Unknown", color: "bg-slate-400" },
] as const;

export default function StaffDashboard({ role, name, onNavigate, onSessionEnd }: Props) {
  const [s, setS] = useState<StaffSummary | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    (async () => {
      const res = await api.get("/api/staff/summary");
      if (res.status === 401) return onSessionEnd();
      if (res.status === 200) setS(res.data as StaffSummary);
      else setError(problem(res).message);
    })();
  }, []);

  const st = s?.stats;
  const cards: { label: string; value: number | undefined; icon: string; color: string; bg: string; go?: string }[] =
    role === "admin"
      ? [
          { label: "Total Users", value: st?.total_users, icon: "👤", color: "text-[#1e3a5f]", bg: "bg-blue-50" },
          { label: "Total Employers", value: st?.total_employers, icon: "🏢", color: "text-purple-600", bg: "bg-purple-50" },
          { label: "Pending Verification", value: st?.pending_employers, icon: "⏳", color: "text-amber-600", bg: "bg-amber-50", go: "employers" },
          { label: "Threat URLs", value: st?.active_threats, icon: "⚠", color: "text-red-600", bg: "bg-red-50", go: "threats" },
        ]
      : [
          { label: "Total Scanned URLs", value: st?.total_scans, icon: "🔍", color: "text-[#1e3a5f]", bg: "bg-blue-50" },
          { label: "Threat URLs", value: st?.active_threats, icon: "⚠", color: "text-red-600", bg: "bg-red-50", go: "threats" },
          { label: "Pending Approvals", value: st?.pending_threats, icon: "⏳", color: "text-amber-600", bg: "bg-amber-50", go: "threats" },
          { label: "User Feedback", value: st?.open_feedback, icon: "✉", color: "text-purple-600", bg: "bg-purple-50", go: "feedback" },
        ];
  const total = s ? s.distribution.safe + s.distribution.suspicious + s.distribution.malicious + s.distribution.unknown : 0;

  return (
    <div className="max-w-5xl space-y-6">
      <div>
        <h2 className="text-xl font-bold text-slate-900">{role === "admin" ? "Admin Dashboard" : "Employer Dashboard"}</h2>
        <p className="text-slate-500 text-sm mt-0.5">
          Welcome, {name}. {role === "admin" ? "System-wide security overview and management." : "Monitor URL security activity and manage approvals."}
        </p>
      </div>
      {error && <Alert kind="error">{error}</Alert>}

      <div className="grid grid-cols-4 gap-4">
        {cards.map((c) => (
          <div key={c.label} className="bg-white rounded-xl border border-slate-200 p-5">
            <div className={`w-9 h-9 ${c.bg} rounded-lg flex items-center justify-center text-base mb-3`}>{c.icon}</div>
            <div className={`text-2xl font-bold ${c.color}`}>{c.value ?? "–"}</div>
            <div className="text-slate-500 text-xs mt-1">{c.label}</div>
            {c.go && (
              <button onClick={() => onNavigate(c.go!)} className="text-[#1e3a5f] text-xs font-medium hover:underline mt-2">Open →</button>
            )}
          </div>
        ))}
      </div>

      <div className="grid grid-cols-2 gap-5">
        <div className="bg-white rounded-xl border border-slate-200 p-5">
          <h3 className="font-semibold text-slate-800 mb-4">System Security Overview</h3>
          {total === 0 ? (
            <p className="text-sm text-slate-400">No scans have been recorded yet.</p>
          ) : (
            <div className="space-y-3">
              {BARS.map((b) => {
                const n = s!.distribution[b.key];
                return (
                  <div key={b.key}>
                    <div className="flex justify-between text-sm mb-1.5">
                      <span className="text-slate-600">{b.label} URLs</span>
                      <span className="text-slate-800 font-medium">{percent(n, total)}% <span className="text-slate-400 font-normal">({n})</span></span>
                    </div>
                    <div className="h-2.5 bg-slate-100 rounded-full overflow-hidden">
                      <div className={`h-full ${b.color} rounded-full`} style={{ width: `${percent(n, total)}%` }} />
                    </div>
                  </div>
                );
              })}
              <p className="text-xs text-slate-400 pt-1">{total} scans in total</p>
            </div>
          )}
        </div>

        <div className="bg-white rounded-xl border border-slate-200 p-5">
          <div className="flex items-center justify-between mb-4">
            <h3 className="font-semibold text-slate-800">Waiting for review</h3>
            <button onClick={() => onNavigate("threats")} className="text-sm text-[#1e3a5f] hover:underline font-medium">Review</button>
          </div>
          {s && s.waiting.length === 0 ? (
            <p className="text-sm text-slate-400">Nothing is waiting for review.</p>
          ) : (
            <ul className="divide-y divide-slate-100">
              {(s?.waiting ?? []).map((w) => (
                <li key={w.id} className="py-2.5 flex items-center gap-3">
                  <span className="flex-1 min-w-0 text-xs font-mono text-slate-700 truncate" title={w.url}>{w.url}</span>
                  <Badge tone={threatTypeTone(w.threat_type)}>{threatTypeLabel(w.threat_type)}</Badge>
                  <StatusBadge level={w.risk_level} />
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>

      {role === "admin" && (
        <div className="bg-white rounded-xl border border-slate-200 p-5">
          <h3 className="font-semibold text-slate-800 mb-4">Recent staff activity</h3>
          {s && (s.activity?.length ?? 0) === 0 ? (
            <p className="text-sm text-slate-400">No review actions yet.</p>
          ) : (
            <ul className="divide-y divide-slate-100">
              {(s?.activity ?? []).map((a, i) => (
                <li key={i} className="py-2.5 flex items-center justify-between text-sm">
                  <span className="text-slate-700">
                    <span className="font-medium">{a.actor ?? "System"}</span> · {activityText(a.action)}
                  </span>
                  <span className="text-slate-400 text-xs">{new Date(a.created_at).toLocaleString()}</span>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </div>
  );
}
