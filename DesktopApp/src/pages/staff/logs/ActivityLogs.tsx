import { useCallback, useEffect, useState } from "react";
import { api, problem } from "../../../api";
import Badge from "../../../components/Badge";
import Pager from "../../../components/Pager";
import { Alert } from "../../../components/ui";
import { actionLabel, logDateTime, LOGS_PER_PAGE, roleLabel, roleTone } from "../../../lib/admin";
import type { ActivityRow, StaffRole } from "../../../lib/admin";

interface Props {
  role: StaffRole;
  onSessionEnd: () => void;
}

const FILTERS: [string, string][] = [
  ["", "All"],
  ["employer", "Employers only"],
  ["admin", "Admins only"],
];

// Administrator: what admins and employers did, filter by who and search a name or email.
// Employer: only their own actions (the server decides; nothing here can widen it).
export default function ActivityLogs({ role, onSessionEnd }: Props) {
  const admin = role === "admin";
  const [actor, setActor] = useState("");
  const [search, setSearch] = useState("");
  const [q, setQ] = useState(""); // the search text, applied 300 ms after typing stops
  const [page, setPage] = useState(1);
  const [rows, setRows] = useState<ActivityRow[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

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
    const qs = new URLSearchParams({ page: String(page), per_page: String(LOGS_PER_PAGE) });
    if (admin && actor) qs.set("actor", actor);
    if (admin && q) qs.set("search", q);
    const res = await api.get(`/api/staff/activity-logs?${qs.toString()}`);
    setLoading(false);
    if (res.status === 401) return onSessionEnd();
    if (res.status !== 200) return setError(problem(res).message);
    setRows(res.data.logs as ActivityRow[]);
    setTotal(res.data.total as number);
  }, [page, actor, q, admin]);

  useEffect(() => {
    load();
  }, [load]);

  const heads = admin ? ["Who", "Action", "Target", "Date/Time", "Status"] : ["Action", "Target", "Date/Time", "Status"];

  return (
    <div className="max-w-5xl space-y-5">
      <div>
        <h2 className="text-xl font-bold text-slate-900">{admin ? "Activity Logs" : "My Activity Logs"}</h2>
        <p className="text-slate-500 text-sm mt-0.5">
          {admin ? "Complete audit trail of admin and employer actions." : "A record of the actions you took in SafeBrowse."}
        </p>
      </div>

      {error && <Alert kind="error">{error}</Alert>}

      {admin && (
        <div className="flex flex-wrap items-center gap-3">
          <div className="inline-flex gap-1 p-1 bg-slate-100 rounded-lg" role="tablist" aria-label="Filter by who acted">
            {FILTERS.map(([value, label]) => (
              <button
                key={value}
                role="tab"
                aria-selected={actor === value}
                onClick={() => {
                  setActor(value);
                  setPage(1);
                }}
                className={`px-4 py-1.5 rounded-md text-sm font-medium ${actor === value ? "bg-white text-[#1e3a5f] shadow-sm" : "text-slate-500 hover:text-slate-700"}`}
              >
                {label}
              </button>
            ))}
          </div>
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            aria-label="Search by name or email"
            maxLength={100}
            placeholder="Search name or email..."
            className="flex-1 min-w-48 px-3.5 py-2 border border-slate-300 rounded-lg text-sm placeholder-slate-400 bg-white focus:outline-none focus:border-[#1e3a5f] focus:ring-2 focus:ring-[#1e3a5f]/10"
          />
        </div>
      )}

      <div className="bg-white rounded-xl border border-slate-200 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="text-xs text-slate-500 bg-slate-50 border-b border-slate-200">
                {heads.map((h) => (
                  <th key={h} className="text-left px-5 py-3 font-medium">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {rows.map((row, i) => (
                <tr key={`${row.created_at}-${i}`} className="hover:bg-slate-50 transition-colors">
                  {admin && (
                    <td className="px-5 py-3.5">
                      <div className="text-sm font-medium text-slate-800">{row.actor}</div>
                      <div className="mt-0.5">
                        <Badge tone={roleTone(row.actor_role)}>{roleLabel(row.actor_role)}</Badge>
                      </div>
                    </td>
                  )}
                  <td className="px-5 py-3.5 text-sm text-slate-700">{actionLabel(row.action)}</td>
                  <td className="px-5 py-3.5 text-sm font-mono text-slate-600 break-all">{row.target}</td>
                  <td className="px-5 py-3.5 text-sm text-slate-500 whitespace-nowrap">{logDateTime(row.created_at)}</td>
                  <td className="px-5 py-3.5">
                    <Badge tone="green">Successful</Badge>
                  </td>
                </tr>
              ))}
              {rows.length === 0 && (
                <tr>
                  <td colSpan={heads.length} className="px-5 py-10 text-center text-slate-400 text-sm">
                    {loading ? "Loading…" : admin && (actor || q) ? "No matching activity." : "No activity recorded yet."}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
        <Pager page={page} perPage={LOGS_PER_PAGE} total={total} onPage={setPage} />
      </div>
    </div>
  );
}
