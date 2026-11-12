import { useCallback, useEffect, useState } from "react";
import { api, problem } from "../../../api";
import Badge from "../../../components/Badge";
import Modal from "../../../components/Modal";
import { Alert } from "../../../components/ui";
import { approvalLabel } from "../../../lib/admin";
import type { ApprovalItem } from "../../../lib/admin";
import { shortDate } from "../../../lib/approvals";

interface Props {
  reloadKey: number;
  onChanged: () => void;
  onSessionEnd: () => void;
}

// Administrator: new administrator accounts and changes to another administrator's account wait here for a decision.
// Nobody decides what they started themselves, and an account never decides about itself.
export default function Approvals({ reloadKey, onChanged, onSessionEnd }: Props) {
  const [items, setItems] = useState<ApprovalItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [open, setOpen] = useState<ApprovalItem | null>(null);
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    const res = await api.get("/api/staff/approvals");
    setLoading(false);
    if (res.status === 401) return onSessionEnd();
    if (res.status !== 200) return setError(problem(res).message);
    setError("");
    setItems(res.data.items as ApprovalItem[]);
  }, [reloadKey]);

  useEffect(() => {
    load();
  }, [load]);

  async function decide(decision: "approve" | "reject") {
    if (!open || busy) return;
    setBusy(true);
    setError("");
    const path = open.kind === "invitation" ? `/api/staff/invitations/${open.id}/decision` : `/api/staff/admin-changes/${open.id}/decision`;
    const res = await api.post(path, { decision, note: note.trim() });
    setBusy(false);
    if (res.status === 401) return onSessionEnd();
    const what = open.title;
    setOpen(null);
    setNote("");
    if (res.status === 200) setNotice(`${what}: ${decision === "approve" ? "approved" : "rejected"}.`);
    else setError(problem(res).message);
    load();
    onChanged();
  }

  const waiting = items.filter((i) => i.status === "pending" || i.status === "awaiting_approval");

  return (
    <div className="space-y-4">
      {error && <Alert kind="error">{error}</Alert>}
      {notice && <Alert kind="success">{notice}</Alert>}
      <p className="text-sm text-slate-500">
        A new administrator account, or a change to another administrator's account, needs a decision from a <b>different</b> administrator.
        {waiting.length === 0 && !loading ? " Nothing is waiting right now." : ""}
      </p>

      <div className="bg-white rounded-xl border border-slate-200 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="text-xs text-slate-500 bg-slate-50 border-b border-slate-200">
                {["Request", "For", "Asked by", "Date", "Status", "Action"].map((h) => (
                  <th key={h} className="text-left px-5 py-3 font-medium">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {items.map((i) => {
                const [label, tone] = approvalLabel(i.status);
                const isWaiting = i.status === "pending" || i.status === "awaiting_approval";
                return (
                  <tr key={`${i.kind}-${i.id}`} className="hover:bg-slate-50 transition-colors">
                    <td className="px-5 py-3.5 text-sm font-medium text-slate-800">{i.title}</td>
                    <td className="px-5 py-3.5 text-sm text-slate-600 break-all">{i.detail}</td>
                    <td className="px-5 py-3.5 text-sm text-slate-600">{i.requested_by}</td>
                    <td className="px-5 py-3.5 text-sm text-slate-500 whitespace-nowrap">{shortDate(i.created_at)}</td>
                    <td className="px-5 py-3.5">
                      <Badge tone={tone}>{label}</Badge>
                      {i.decided_by && <div className="text-xs text-slate-400 mt-1">by {i.decided_by}</div>}
                    </td>
                    <td className="px-5 py-3.5">
                      {isWaiting && i.can_decide ? (
                        <button onClick={() => { setNotice(""); setNote(""); setOpen(i); }} className="text-[#1e3a5f] text-sm font-medium hover:underline">
                          Review
                        </button>
                      ) : isWaiting ? (
                        <span className="text-xs text-slate-400">Another administrator decides</span>
                      ) : (
                        <span className="text-slate-300">—</span>
                      )}
                    </td>
                  </tr>
                );
              })}
              {items.length === 0 && (
                <tr>
                  <td colSpan={6} className="px-5 py-10 text-center text-slate-400 text-sm">
                    {loading ? "Loading…" : "No approvals yet."}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {open && (
        <Modal
          title={open.title}
          subtitle={`Asked by ${open.requested_by}`}
          onClose={() => setOpen(null)}
          footer={
            <>
              <button onClick={() => setOpen(null)} className="flex-1 border border-slate-300 text-slate-700 py-2.5 rounded-lg text-sm font-medium hover:bg-slate-50">
                Cancel
              </button>
              <button onClick={() => decide("reject")} disabled={busy} className="flex-1 border border-red-300 text-red-600 py-2.5 rounded-lg text-sm font-semibold hover:bg-red-50 disabled:opacity-60">
                Reject
              </button>
              <button onClick={() => decide("approve")} disabled={busy} className="flex-1 bg-green-600 text-white py-2.5 rounded-lg text-sm font-semibold hover:bg-green-700 disabled:opacity-60">
                {busy ? "Please wait…" : "Approve"}
              </button>
            </>
          }
        >
          <div className="space-y-4 text-sm">
            <div className="bg-slate-50 border border-slate-200 rounded-xl p-3.5">
              <p className="text-slate-500 text-xs mb-1">For</p>
              <p className="font-medium text-slate-800 break-all">{open.detail}</p>
            </div>
            <p className="text-xs text-slate-500">
              {open.kind === "invitation"
                ? "If you approve, an email with a code is sent to this address now. To use it the person also needs the PIN that the administrator who asked will tell them. Check that the address is the right person's."
                : "If you approve, the change is carried out at once. The administrator is signed out everywhere when the account is deactivated or deleted."}
            </p>
            <div>
              <label htmlFor="ap-note" className="block text-sm font-medium text-slate-700 mb-1.5">
                Note <span className="text-slate-400 font-normal">(optional)</span>
              </label>
              <textarea id="ap-note" value={note} maxLength={1000} onChange={(e) => setNote(e.target.value)} rows={3}
                        className="w-full px-3.5 py-2.5 border border-slate-300 rounded-lg text-sm placeholder-slate-400 focus:outline-none focus:border-[#1e3a5f] focus:ring-2 focus:ring-[#1e3a5f]/10 resize-none" />
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
}
