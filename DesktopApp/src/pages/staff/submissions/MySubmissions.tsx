import { useCallback, useEffect, useState } from "react";
import { api, problem } from "../../../api";
import Badge from "../../../components/Badge";
import Modal from "../../../components/Modal";
import Pager from "../../../components/Pager";
import { Alert } from "../../../components/ui";
import { categoryLabel, categoryTone, reviewLabel, reviewTone, REVIEW_PER_PAGE, scoreClass, shortDate, shortDateTime } from "../../../lib/approvals";
import type { ThreatSubmission } from "../../../lib/approvals";

interface Props {
  onSessionEnd: () => void;
  /** changes when a new submission was sent, so the list reloads */
  reloadKey: number;
}

// Employer: the threat URLs I submitted and what the administrators decided.
export default function MySubmissions({ onSessionEnd, reloadKey }: Props) {
  const [rows, setRows] = useState<ThreatSubmission[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [view, setView] = useState<ThreatSubmission | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    const res = await api.get(`/api/staff/threat-submissions/mine?page=${page}&per_page=${REVIEW_PER_PAGE}`);
    setLoading(false);
    if (res.status === 401) return onSessionEnd();
    if (res.status !== 200) return setError(problem(res).message);
    setRows(res.data.submissions as ThreatSubmission[]);
    setTotal(res.data.total as number);
  }, [page, reloadKey]);

  useEffect(() => {
    load();
  }, [load]);

  return (
    <div className="bg-white rounded-xl border border-slate-200 overflow-hidden">
      <div className="px-5 py-4 border-b border-slate-100">
        <h3 className="font-semibold text-slate-800">My Submissions</h3>
        <p className="text-slate-500 text-xs mt-0.5">Track approval status of your submitted threat URLs.</p>
      </div>
      {error && (
        <div className="px-5 pt-4">
          <Alert kind="error">{error}</Alert>
        </div>
      )}
      {rows.length === 0 ? (
        <div className="px-5 py-12 text-center text-slate-400 text-sm">
          {loading ? (
            "Loading…"
          ) : (
            <>
              No submissions yet. Use <b>Submit Threat URL</b> to report a malicious site.
            </>
          )}
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="text-xs text-slate-500 bg-slate-50 border-b border-slate-200">
                {["URL", "Type", "Risk Score", "Submitted", "Review Status", "Action"].map((h) => (
                  <th key={h} className="text-left px-5 py-3 font-medium">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {rows.map((sub) => (
                <tr key={sub.id} className="hover:bg-slate-50 transition-colors">
                  <td className="px-5 py-3.5 text-sm font-mono text-slate-700 max-w-xs truncate" title={sub.url}>
                    {sub.url}
                  </td>
                  <td className="px-5 py-3.5">
                    <Badge tone={categoryTone(sub.category)}>{categoryLabel(sub.category)}</Badge>
                  </td>
                  <td className="px-5 py-3.5 text-sm font-semibold">
                    <span className={scoreClass(sub.risk_score)}>{Math.round(sub.risk_score)}/100</span>
                  </td>
                  <td className="px-5 py-3.5 text-sm text-slate-500 whitespace-nowrap">{shortDate(sub.created_at)}</td>
                  <td className="px-5 py-3.5">
                    <Badge tone={reviewTone(sub.status)}>{reviewLabel(sub.status)}</Badge>
                  </td>
                  <td className="px-5 py-3.5">
                    <button onClick={() => setView(sub)} className="text-[#1e3a5f] text-sm font-medium hover:underline">
                      View
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <Pager page={page} perPage={REVIEW_PER_PAGE} total={total} onPage={setPage} />

      {view && (
        <Modal
          title="Submission Details"
          onClose={() => setView(null)}
          footer={
            <button onClick={() => setView(null)} className="w-full border border-slate-300 text-slate-700 py-2.5 rounded-lg text-sm font-medium hover:bg-slate-50">
              Close
            </button>
          }
        >
          <div className="space-y-4">
            <div className={`flex items-center gap-3 p-3.5 rounded-xl border ${view.status === "approved" ? "bg-green-50 text-green-700 border-green-200" : view.status === "rejected" ? "bg-red-50 text-red-700 border-red-200" : "bg-amber-50 text-amber-700 border-amber-200"}`}>
              <span className="text-lg">{view.status === "approved" ? "✓" : view.status === "rejected" ? "✗" : "⏳"}</span>
              <div>
                <p className="text-sm font-semibold">
                  {view.status === "pending" ? "Awaiting Admin Review" : view.status === "approved" ? "Approved — Published to Global List" : "Rejected by Admin"}
                </p>
                <p className="text-xs mt-0.5 opacity-80">Submitted on {shortDateTime(view.created_at)}</p>
              </div>
            </div>
            <div className="divide-y divide-slate-100">
              {(
                [
                  ["URL", <span className="font-mono text-xs break-all">{view.url}</span>],
                  ["Category", <Badge tone={categoryTone(view.category)}>{categoryLabel(view.category)}</Badge>],
                  ["Risk Score", <span className={`font-bold ${scoreClass(view.risk_score)}`}>{Math.round(view.risk_score)}/100</span>],
                ] as [string, React.ReactNode][]
              ).map(([l, v]) => (
                <div key={l} className="flex items-center justify-between py-2.5 text-sm gap-4">
                  <span className="text-slate-500">{l}</span>
                  <div className="text-right min-w-0">{v}</div>
                </div>
              ))}
            </div>
            <div>
              <p className="text-slate-500 text-xs mb-1">Your Notes</p>
              <p className="text-slate-700 text-sm leading-relaxed whitespace-pre-wrap">{view.notes}</p>
            </div>
            {view.review_note && (
              <div className="bg-slate-50 border border-slate-200 rounded-xl p-3.5">
                <p className="text-slate-500 text-xs mb-1">Admin Response</p>
                <p className="text-slate-700 text-sm leading-relaxed whitespace-pre-wrap">{view.review_note}</p>
              </div>
            )}
          </div>
        </Modal>
      )}
    </div>
  );
}
