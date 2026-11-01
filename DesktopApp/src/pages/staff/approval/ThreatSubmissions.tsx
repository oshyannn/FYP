import { useCallback, useEffect, useState } from "react";
import { api, problem } from "../../../api";
import Badge from "../../../components/Badge";
import ConfirmDialog from "../../../components/ConfirmDialog";
import Modal from "../../../components/Modal";
import Pager from "../../../components/Pager";
import { Alert } from "../../../components/ui";
import {
  categoryLabel, categoryTone, reviewLabel, reviewTone, REVIEW_PER_PAGE, scoreBarClass, scoreClass, shortDate, shortDateTime,
} from "../../../lib/approvals";
import type { ThreatSubmission } from "../../../lib/approvals";

interface Props {
  onSessionEnd: () => void;
  onChanged: () => void;
}

interface Counts {
  total: number;
  pending: number;
  reviewed: number;
}

type Action = "approve" | "reject";

// Administrator: threat URLs reported by employers. Approving publishes the URL to the Global Threat List.
export default function ThreatSubmissions({ onSessionEnd, onChanged }: Props) {
  const [rows, setRows] = useState<ThreatSubmission[]>([]);
  const [counts, setCounts] = useState<Counts>({ total: 0, pending: 0, reviewed: 0 });
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [done, setDone] = useState("");
  const [selected, setSelected] = useState<ThreatSubmission | null>(null);
  const [note, setNote] = useState("");
  const [confirm, setConfirm] = useState<Action | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    const res = await api.get(`/api/staff/threat-submissions?page=${page}&per_page=${REVIEW_PER_PAGE}`);
    setLoading(false);
    if (res.status === 401) return onSessionEnd();
    if (res.status !== 200) return setError(problem(res).message);
    setRows(res.data.submissions as ThreatSubmission[]);
    setTotal(res.data.total as number);
    setCounts(res.data.counts as Counts);
  }, [page]);

  useEffect(() => {
    load();
  }, [load]);

  async function decide() {
    if (!selected || !confirm || busy) return;
    setBusy(true);
    setError("");
    const res = await api.post(`/api/staff/threat-submissions/${selected.id}/review`, { decision: confirm, note: note.trim() });
    setBusy(false);
    if (res.status === 401) return onSessionEnd();
    const url = selected.url;
    const action = confirm;
    setConfirm(null);
    setSelected(null);
    setNote("");
    if (res.status === 200) setDone(action === "approve" ? `${url} was published to the Global Threat List.` : `${url} was rejected.`);
    else setError(problem(res).message);
    load();
    onChanged();
  }

  const cards = [
    { label: "Total Submissions", value: counts.total, color: "text-slate-800", bg: "bg-slate-50" },
    { label: "Pending Review", value: counts.pending, color: "text-amber-600", bg: "bg-amber-50" },
    { label: "Reviewed", value: counts.reviewed, color: "text-green-600", bg: "bg-green-50" },
  ];

  return (
    <>
      {error && <Alert kind="error">{error}</Alert>}
      {done && <Alert kind="success">{done}</Alert>}

      <div className="grid grid-cols-3 gap-4">
        {cards.map((c) => (
          <div key={c.label} className={`${c.bg} rounded-xl border border-slate-200 p-4 text-center`}>
            <div className={`text-2xl font-bold ${c.color}`}>{c.value}</div>
            <div className="text-slate-500 text-xs mt-1">{c.label}</div>
          </div>
        ))}
      </div>

      <div className="bg-white rounded-xl border border-slate-200 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="text-xs text-slate-500 bg-slate-50 border-b border-slate-200">
                {["URL", "Type", "Risk Score", "Submitted By", "Submitted Date", "Status", "Action"].map((h) => (
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
                  <td className="px-5 py-3.5 text-sm text-slate-600">{sub.submitted_by_email}</td>
                  <td className="px-5 py-3.5 text-sm text-slate-500 whitespace-nowrap">{shortDate(sub.created_at)}</td>
                  <td className="px-5 py-3.5">
                    <Badge tone={reviewTone(sub.status)}>{reviewLabel(sub.status)}</Badge>
                  </td>
                  <td className="px-5 py-3.5">
                    <button
                      onClick={() => {
                        setDone("");
                        setNote("");
                        setConfirm(null);
                        setSelected(sub);
                      }}
                      className="text-[#1e3a5f] text-sm font-medium hover:underline"
                    >
                      Review
                    </button>
                  </td>
                </tr>
              ))}
              {rows.length === 0 && (
                <tr>
                  <td colSpan={7} className="px-5 py-10 text-center text-slate-400 text-sm">
                    {loading ? "Loading…" : "No threat URL submissions yet."}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
        <Pager page={page} perPage={REVIEW_PER_PAGE} total={total} onPage={setPage} />
      </div>

      {selected && (
        <Modal
          title="Review Threat Submission"
          subtitle={`Submitted by ${selected.submitted_by_email}`}
          onClose={() => setSelected(null)}
          footer={
            <>
              <button onClick={() => setSelected(null)} className="flex-1 border border-slate-300 text-slate-700 py-2.5 rounded-lg text-sm font-medium hover:bg-slate-50">
                {selected.status === "pending" ? "Cancel" : "Close"}
              </button>
              {selected.status === "pending" && (
                <>
                  <button onClick={() => setConfirm("reject")} className="flex-1 border border-red-300 text-red-600 py-2.5 rounded-lg text-sm font-semibold hover:bg-red-50">
                    Reject
                  </button>
                  <button onClick={() => setConfirm("approve")} className="flex-1 bg-green-600 text-white py-2.5 rounded-lg text-sm font-semibold hover:bg-green-700">
                    Approve &amp; Publish
                  </button>
                </>
              )}
            </>
          }
        >
          <div className="space-y-4">
            <div className="divide-y divide-slate-100">
              {(
                [
                  ["URL", <span className="font-mono text-xs text-slate-800 break-all">{selected.url}</span>],
                  ["Category", <Badge tone={categoryTone(selected.category)}>{categoryLabel(selected.category)}</Badge>],
                  ["Risk Score", <span className={`font-bold ${scoreClass(selected.risk_score)}`}>{Math.round(selected.risk_score)}/100</span>],
                  [
                    "Risk bar",
                    <div className="w-32 h-2 bg-slate-100 rounded-full overflow-hidden">
                      <div className={`h-full rounded-full ${scoreBarClass(selected.risk_score)}`} style={{ width: `${selected.risk_score}%` }} />
                    </div>,
                  ],
                  ["Source", <span className="text-slate-700">Employer Report</span>],
                  ["Submitted", <span className="text-slate-700">{shortDateTime(selected.created_at)}</span>],
                ] as [string, React.ReactNode][]
              ).map(([l, v]) => (
                <div key={l} className="flex items-center justify-between py-2.5 text-sm gap-4">
                  <span className="text-slate-500 shrink-0">{l}</span>
                  <div className="text-right">{v}</div>
                </div>
              ))}
            </div>

            <div className="bg-slate-50 border border-slate-200 rounded-xl p-3.5">
              <p className="text-slate-500 text-xs mb-1.5 font-medium">Employer Notes</p>
              <p className="text-slate-700 text-sm leading-relaxed whitespace-pre-wrap">{selected.notes}</p>
            </div>

            {selected.status !== "pending" && (
              <div className={`p-3 rounded-xl border text-sm ${selected.status === "approved" ? "bg-green-50 text-green-700 border-green-200" : "bg-red-50 text-red-700 border-red-200"}`}>
                <p className="font-medium">{selected.status === "approved" ? "✓ Approved — Published to Global Threat List" : "✗ Rejected"}</p>
                <p className="text-xs mt-0.5 opacity-80">
                  {selected.reviewed_by_name ? `by ${selected.reviewed_by_name}` : ""}
                  {selected.reviewed_at ? ` on ${shortDate(selected.reviewed_at)}` : ""}
                </p>
                {selected.review_note && <p className="text-xs mt-1">Note: {selected.review_note}</p>}
              </div>
            )}

            {selected.status === "pending" && (
              <div>
                <label htmlFor="review-note" className="block text-sm font-medium text-slate-700 mb-1.5">
                  Review Note <span className="text-slate-400 font-normal">(optional)</span>
                </label>
                <textarea
                  id="review-note"
                  value={note}
                  maxLength={1000}
                  onChange={(e) => setNote(e.target.value)}
                  rows={3}
                  placeholder="Add a note for the employer about your decision..."
                  className="w-full px-3.5 py-2.5 border border-slate-300 rounded-lg text-sm placeholder-slate-400 focus:outline-none focus:border-[#1e3a5f] focus:ring-2 focus:ring-[#1e3a5f]/10 resize-none"
                />
              </div>
            )}
          </div>
        </Modal>
      )}

      {confirm && selected && (
        <ConfirmDialog
          title={confirm === "approve" ? "Approve & Publish?" : "Reject Submission?"}
          tone={confirm === "approve" ? "green" : "red"}
          busy={busy}
          onConfirm={decide}
          onCancel={() => setConfirm(null)}
        >
          <p className="font-mono mb-1 break-all">{selected.url}</p>
          <p>
            {confirm === "approve"
              ? "This URL will be immediately published to the Global Threat List, visible to all users."
              : "The submission will be rejected and the employer will see your note."}
          </p>
        </ConfirmDialog>
      )}
    </>
  );
}
