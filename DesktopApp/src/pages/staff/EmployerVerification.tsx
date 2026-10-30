import { useCallback, useEffect, useState } from "react";
import { api, problem } from "../../api";
import Badge from "../../components/Badge";
import { Alert } from "../../components/ui";
import { applicationLabel, applicationTone } from "../../lib/threats";
import type { Application } from "../../lib/threats";

interface Props {
  onSessionEnd: () => void;
}

const PER_PAGE = 10;
type Filter = "" | "pending" | "approved" | "rejected";

export default function EmployerVerification({ onSessionEnd }: Props) {
  const [filter, setFilter] = useState<Filter>("pending");
  const [search, setSearch] = useState("");
  const [q, setQ] = useState("");
  const [page, setPage] = useState(1);
  const [rows, setRows] = useState<Application[]>([]);
  const [total, setTotal] = useState(0);
  const [counts, setCounts] = useState({ pending: 0, approved: 0, rejected: 0 });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [done, setDone] = useState("");
  const [sel, setSel] = useState<Application | null>(null);
  const [asking, setAsking] = useState<"approve" | "reject" | null>(null);
  const [remarks, setRemarks] = useState("");
  const [fieldError, setFieldError] = useState("");
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
    if (filter) qs.set("status", filter);
    if (q) qs.set("search", q);
    const res = await api.get(`/api/admin/employers?${qs.toString()}`);
    setLoading(false);
    if (res.status === 401) return onSessionEnd();
    if (res.status !== 200) return setError(problem(res).message);
    setRows(res.data.applications as Application[]);
    setTotal(res.data.total as number);
    setCounts(res.data.counts);
  }, [filter, q, page]);

  useEffect(() => {
    load();
  }, [load]);

  function open(a: Application) {
    setSel(a);
    setAsking(null);
    setRemarks("");
    setFieldError("");
    setDone("");
  }

  async function submit() {
    if (!sel || !asking || busy) return;
    if (asking === "reject" && remarks.trim().length < 3) {
      setFieldError("Give a reason for rejecting.");
      return;
    }
    setBusy(true);
    const res = await api.post(`/api/admin/employers/${sel.id}/review`, { decision: asking, remarks: remarks.trim() });
    setBusy(false);
    if (res.status === 401) return onSessionEnd();
    if (res.status === 200) {
      setDone(asking === "approve" ? "Employer approved. They can now log in to the staff portal." : "Application rejected.");
      setSel(null);
      load();
    } else {
      const p = problem(res);
      setFieldError(p.fields.remarks ?? p.message);
    }
  }

  const pages = Math.max(1, Math.ceil(total / PER_PAGE));
  const chips: { key: Filter; label: string; n?: number; cls: string }[] = [
    { key: "pending", label: "Pending", n: counts.pending, cls: "bg-amber-50 border-amber-200 text-amber-700" },
    { key: "approved", label: "Approved", n: counts.approved, cls: "bg-green-50 border-green-200 text-green-700" },
    { key: "rejected", label: "Rejected", n: counts.rejected, cls: "bg-red-50 border-red-200 text-red-700" },
    { key: "", label: "All", cls: "bg-slate-50 border-slate-200 text-slate-700" },
  ];

  return (
    <div className="max-w-5xl space-y-5">
      <div>
        <h2 className="text-xl font-bold text-slate-900">Employer Verification</h2>
        <p className="text-slate-500 text-sm mt-0.5">Review and approve employer account applications.</p>
      </div>

      {error && <Alert kind="error">{error}</Alert>}
      {done && <Alert kind="success">{done}</Alert>}

      <div className="flex flex-wrap gap-3">
        {chips.map((c) => (
          <button
            key={c.label}
            onClick={() => { setFilter(c.key); setPage(1); setDone(""); }}
            aria-pressed={filter === c.key}
            className={`border rounded-xl px-5 py-3 text-sm font-semibold ${c.cls} ${filter === c.key ? "ring-2 ring-[#1e3a5f]/40" : "opacity-80 hover:opacity-100"}`}
          >
            {c.n !== undefined ? `${c.n} ` : ""}{c.label}
          </button>
        ))}
        <input
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          maxLength={100}
          aria-label="Search applications"
          placeholder="Search name, email or company..."
          className="flex-1 min-w-48 px-3.5 py-2 border border-slate-300 rounded-lg text-sm placeholder-slate-400 bg-white focus:outline-none focus:border-[#1e3a5f] focus:ring-2 focus:ring-[#1e3a5f]/10"
        />
      </div>

      <div className="bg-white rounded-xl border border-slate-200 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="text-xs text-slate-500 bg-slate-50 border-b border-slate-200">
                {["Employer Name", "Company", "Email", "Submitted Date", "Status", "Action"].map((h) => (
                  <th key={h} className="text-left px-5 py-3 font-medium">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {rows.map((r) => (
                <tr key={r.id} className="hover:bg-slate-50 transition-colors">
                  <td className="px-5 py-3.5 text-sm font-medium text-slate-800">{r.name ?? "—"}</td>
                  <td className="px-5 py-3.5 text-sm text-slate-600">{r.company_name}</td>
                  <td className="px-5 py-3.5 text-sm text-slate-600">{r.email}</td>
                  <td className="px-5 py-3.5 text-sm text-slate-500">{new Date(r.submitted_at).toLocaleDateString()}</td>
                  <td className="px-5 py-3.5"><Badge tone={applicationTone(r.status)}>{applicationLabel(r.status)}</Badge></td>
                  <td className="px-5 py-3.5">
                    <button onClick={() => open(r)} className="text-[#1e3a5f] text-sm font-medium hover:underline">Review</button>
                  </td>
                </tr>
              ))}
              {rows.length === 0 && (
                <tr>
                  <td colSpan={6} className="px-5 py-10 text-center text-slate-400 text-sm">
                    {loading ? "Loading…" : "No applications found."}
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

      {sel && (
        <div className="fixed inset-0 z-50 bg-black/40 flex items-center justify-center p-4" role="dialog" aria-modal="true" aria-labelledby="ev-title">
          <div className="bg-white rounded-2xl p-6 max-w-md w-full shadow-xl space-y-4">
            <h3 id="ev-title" className="font-semibold text-slate-900">Employer Application</h3>
            <div className="divide-y divide-slate-100 text-sm">
              {([
                ["Name", sel.name ?? "—"],
                ["Email", sel.email],
                ["Company", sel.company_name],
                ["Registration no.", sel.company_registration_no],
                ["Submitted", new Date(sel.submitted_at).toLocaleString()],
                ["Email verified", sel.email_verified ? "Yes" : "Not yet"],
                ["Status", applicationLabel(sel.status)],
                ...(sel.reviewed_at ? [["Reviewed", `${new Date(sel.reviewed_at).toLocaleString()}${sel.reviewed_by_name ? ` by ${sel.reviewed_by_name}` : ""}`]] : []),
                ...(sel.remarks ? [["Remarks", sel.remarks]] : []),
              ] as [string, string][]).map(([l, v]) => (
                <div key={l} className="flex justify-between gap-4 py-2.5">
                  <span className="text-slate-500 shrink-0">{l}</span>
                  <span className="text-slate-800 font-medium text-right break-words min-w-0">{v}</span>
                </div>
              ))}
            </div>

            {!sel.email_verified && sel.status !== "approved" && (
              <Alert kind="info">The applicant has not verified their email yet, so they cannot be approved.</Alert>
            )}

            {asking === "reject" && (
              <div>
                <label htmlFor="ev-remarks" className="block text-sm font-medium text-slate-700 mb-1.5">Reason (required)</label>
                <textarea
                  id="ev-remarks"
                  value={remarks}
                  onChange={(e) => { setRemarks(e.target.value); setFieldError(""); }}
                  maxLength={1000}
                  rows={3}
                  className="w-full px-3.5 py-2.5 border border-slate-300 rounded-lg text-sm focus:outline-none focus:border-[#1e3a5f] focus:ring-2 focus:ring-[#1e3a5f]/10 resize-none"
                />
              </div>
            )}
            {asking === "approve" && (
              <div>
                <label htmlFor="ev-notes" className="block text-sm font-medium text-slate-700 mb-1.5">Remarks (optional)</label>
                <input
                  id="ev-notes"
                  value={remarks}
                  onChange={(e) => setRemarks(e.target.value)}
                  maxLength={1000}
                  className="w-full px-3.5 py-2.5 border border-slate-300 rounded-lg text-sm focus:outline-none focus:border-[#1e3a5f] focus:ring-2 focus:ring-[#1e3a5f]/10"
                />
              </div>
            )}
            {fieldError && <p className="text-xs text-red-600" role="alert">{fieldError}</p>}

            <div className="flex gap-3 pt-1">
              {asking ? (
                <>
                  <button onClick={() => { setAsking(null); setFieldError(""); }} className="flex-1 border border-slate-300 text-slate-700 py-2.5 rounded-lg text-sm font-medium">Back</button>
                  <button
                    onClick={submit}
                    disabled={busy}
                    className={`flex-1 py-2.5 rounded-lg text-sm font-semibold text-white disabled:opacity-60 ${asking === "approve" ? "bg-green-600 hover:bg-green-700" : "bg-red-600 hover:bg-red-700"}`}
                  >
                    {busy ? "Please wait…" : asking === "approve" ? "Confirm approval" : "Confirm rejection"}
                  </button>
                </>
              ) : (
                <>
                  <button onClick={() => setSel(null)} className="flex-1 border border-slate-300 text-slate-700 py-2.5 rounded-lg text-sm font-medium">Close</button>
                  {sel.status !== "rejected" && (
                    <button onClick={() => setAsking("reject")} className="flex-1 border border-red-300 text-red-600 py-2.5 rounded-lg text-sm font-medium hover:bg-red-50">
                      {sel.status === "approved" ? "Revoke approval" : "Reject"}
                    </button>
                  )}
                  {sel.status !== "approved" && (
                    <button
                      onClick={() => setAsking("approve")}
                      disabled={!sel.email_verified}
                      className="flex-1 bg-green-600 text-white py-2.5 rounded-lg text-sm font-semibold hover:bg-green-700 disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                      Approve
                    </button>
                  )}
                </>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
