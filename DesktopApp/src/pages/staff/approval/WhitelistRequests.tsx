import { useCallback, useEffect, useState } from "react";
import { api, problem } from "../../../api";
import Badge from "../../../components/Badge";
import ConfirmDialog from "../../../components/ConfirmDialog";
import Modal from "../../../components/Modal";
import Pager from "../../../components/Pager";
import StatusBadge from "../../../components/StatusBadge";
import { Alert } from "../../../components/ui";
import { reviewLabel, reviewTone, REVIEW_PER_PAGE, scoreClass, shortDate } from "../../../lib/approvals";
import type { WhitelistRequest } from "../../../lib/approvals";

interface Props {
  onSessionEnd: () => void;
  /** called after a decision so the tab badges can refresh */
  onChanged: () => void;
}

type Action = "approve" | "reject";

export default function WhitelistRequests({ onSessionEnd, onChanged }: Props) {
  const [rows, setRows] = useState<WhitelistRequest[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [done, setDone] = useState("");
  const [selected, setSelected] = useState<WhitelistRequest | null>(null);
  const [confirm, setConfirm] = useState<Action | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    const res = await api.get(`/api/staff/whitelist-requests?page=${page}&per_page=${REVIEW_PER_PAGE}`);
    setLoading(false);
    if (res.status === 401) return onSessionEnd();
    if (res.status !== 200) return setError(problem(res).message);
    setRows(res.data.requests as WhitelistRequest[]);
    setTotal(res.data.total as number);
  }, [page]);

  useEffect(() => {
    load();
  }, [load]);

  async function decide() {
    if (!selected || !confirm || busy) return;
    setBusy(true);
    setError("");
    const res = await api.post(`/api/staff/whitelist-requests/${selected.id}/review`, { decision: confirm });
    setBusy(false);
    if (res.status === 401) return onSessionEnd();
    const domain = selected.domain;
    const action = confirm;
    setConfirm(null);
    setSelected(null);
    if (res.status === 200) setDone(`${domain} was ${action === "approve" ? "approved and added to the shared whitelist (trusted for every user)" : "rejected"}.`);
    else setError(problem(res).message);
    load();
    onChanged();
  }

  return (
    <>
      {error && <Alert kind="error">{error}</Alert>}
      {done && <Alert kind="success">{done}</Alert>}

      <div className="bg-white rounded-xl border border-slate-200 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="text-xs text-slate-500 bg-slate-50 border-b border-slate-200">
                {["URL", "Submitted By", "Date", "Risk Score", "Status", "Action"].map((h) => (
                  <th key={h} className="text-left px-5 py-3 font-medium">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {rows.map((row) => (
                <tr key={row.id} className="hover:bg-slate-50 transition-colors">
                  <td className="px-5 py-3.5 text-sm font-mono text-slate-700">{row.domain}</td>
                  <td className="px-5 py-3.5 text-sm text-slate-600">{row.requester_email}</td>
                  <td className="px-5 py-3.5 text-sm text-slate-500 whitespace-nowrap">{shortDate(row.created_at)}</td>
                  <td className="px-5 py-3.5 text-sm font-semibold">
                    {row.risk_score === null ? (
                      <span className="text-slate-400" title="The detector had no data about this website">
                        —
                      </span>
                    ) : (
                      <span className={scoreClass(row.risk_score)}>{Math.round(row.risk_score)}/100</span>
                    )}
                  </td>
                  <td className="px-5 py-3.5">
                    <Badge tone={reviewTone(row.status)}>{reviewLabel(row.status)}</Badge>
                  </td>
                  <td className="px-5 py-3.5">
                    <button
                      onClick={() => {
                        setDone("");
                        setSelected(row);
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
                  <td colSpan={6} className="px-5 py-10 text-center text-slate-400 text-sm">
                    {loading ? "Loading…" : "No whitelist requests yet."}
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
          title="Whitelist Request Review"
          onClose={() => setSelected(null)}
          footer={
            selected.status === "pending" ? (
              <>
                <button onClick={() => setSelected(null)} className="flex-1 border border-slate-300 text-slate-700 py-2.5 rounded-lg text-sm font-medium hover:bg-slate-50">
                  Cancel
                </button>
                <button onClick={() => setConfirm("reject")} className="flex-1 border border-red-300 text-red-600 py-2.5 rounded-lg text-sm font-medium hover:bg-red-50">
                  Reject
                </button>
                <button onClick={() => setConfirm("approve")} className="flex-1 bg-green-600 text-white py-2.5 rounded-lg text-sm font-semibold hover:bg-green-700">
                  Approve
                </button>
              </>
            ) : (
              <button onClick={() => setSelected(null)} className="w-full border border-slate-300 text-slate-700 py-2.5 rounded-lg text-sm font-medium hover:bg-slate-50">
                Close
              </button>
            )
          }
        >
          <div className="divide-y divide-slate-100 text-sm">
            {(
              [
                ["URL", <span className="font-mono text-slate-800 break-all">{selected.domain}</span>],
                ["Submitted By", <span className="text-slate-800">{selected.requester_email}</span>],
                ["Requested", <span className="text-slate-800">{shortDate(selected.created_at)}</span>],
                [
                  "Risk Score",
                  selected.risk_score === null ? (
                    <span className="text-slate-500">Not available</span>
                  ) : (
                    <span className={`font-bold ${scoreClass(selected.risk_score)}`}>{Math.round(selected.risk_score)}/100</span>
                  ),
                ],
                ["Detector verdict", <StatusBadge level={selected.risk_level} />],
                ["Reason", <span className="text-slate-800">{selected.reason || "Not provided"}</span>],
              ] as [string, React.ReactNode][]
            ).map(([l, v]) => (
              <div key={l} className="flex items-center justify-between py-2.5 gap-4">
                <span className="text-slate-500 shrink-0">{l}</span>
                <div className="text-right min-w-0">{v}</div>
              </div>
            ))}
          </div>

          {selected.status === "pending" && selected.risk_level === "malicious" && (
            <p className="mt-4 text-xs text-red-700 bg-red-50 border border-red-200 rounded-lg p-3">
              The detector found this website malicious. Even if approved, scans will keep showing it as malicious.
            </p>
          )}
          {selected.status !== "pending" && (
            <p className="mt-4 text-xs text-slate-500">
              {reviewLabel(selected.status)}
              {selected.reviewed_by_name ? ` by ${selected.reviewed_by_name}` : ""}
              {selected.reviewed_at ? ` on ${shortDate(selected.reviewed_at)}` : ""}.
            </p>
          )}
        </Modal>
      )}

      {confirm && selected && (
        <ConfirmDialog
          title={confirm === "approve" ? "Confirm Approval" : "Confirm Rejection"}
          tone={confirm === "approve" ? "green" : "red"}
          busy={busy}
          onConfirm={decide}
          onCancel={() => setConfirm(null)}
        >
          <p className="font-mono mb-1 break-all">{selected.domain}</p>
          <p>
            {confirm === "approve"
              ? "This website will be added to the shared whitelist and trusted for every SafeBrowse user, not only the person who asked."
              : `Are you sure you want to reject this whitelist request?`}
          </p>
        </ConfirmDialog>
      )}
    </>
  );
}
