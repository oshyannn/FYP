import { useCallback, useEffect, useState } from "react";
import { api, problem } from "../../../api";
import Modal from "../../../components/Modal";
import { Alert } from "../../../components/ui";
import { shortDate } from "../../../lib/approvals";

interface ResetRequest {
  id: string;
  status: string;
  created_at: string;
  account: string;
  email: string;
  role: "user" | "employer" | "admin";
}

interface Props {
  reloadKey: number;
  onChanged: () => void;
  onSessionEnd: () => void;
}

const ROLE_LABEL: Record<ResetRequest["role"], string> = { user: "User", employer: "Employer", admin: "Administrator" };

// Administrator: employers (and other administrators) who forgot their password wait here. Approving sets a random temporary
// password and emails it to the account's own address; the approver never sees it. The person must choose their own password
// at the next login. An administrator cannot decide for their own account.
export default function PasswordResets({ reloadKey, onChanged, onSessionEnd }: Props) {
  const [items, setItems] = useState<ResetRequest[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [open, setOpen] = useState<ResetRequest | null>(null);
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    const res = await api.get("/api/staff/reset-requests");
    setLoading(false);
    if (res.status === 401) return onSessionEnd();
    if (res.status !== 200) return setError(problem(res).message);
    setError("");
    setItems(res.data.requests as ResetRequest[]);
  }, [reloadKey]);

  useEffect(() => {
    load();
  }, [load]);

  async function decide(decision: "approve" | "reject") {
    if (!open || busy) return;
    setBusy(true);
    setError("");
    const res = await api.post(`/api/staff/reset-requests/${open.id}/decision`, { decision, note: note.trim() });
    setBusy(false);
    if (res.status === 401) return onSessionEnd();
    const who = open.email;
    setOpen(null);
    setNote("");
    if (res.status === 200) {
      setNotice(decision === "approve" ? `Approved. A temporary password was emailed to ${who}.` : `Rejected. Nothing was sent to ${who}.`);
    } else setError(problem(res).message);
    load();
    onChanged();
  }

  return (
    <div className="space-y-4">
      {error && <Alert kind="error">{error}</Alert>}
      {notice && <Alert kind="success">{notice}</Alert>}
      <p className="text-sm text-slate-500">
        When an employer or administrator forgets their password, the request waits here. If you approve, they get an email with a temporary
        password and must choose their own at the next login. You never see the password.
        {items.length === 0 && !loading ? " Nothing is waiting right now." : ""}
      </p>

      <div className="bg-white rounded-xl border border-slate-200 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="text-xs text-slate-500 bg-slate-50 border-b border-slate-200">
                {["Account", "Email", "Role", "Requested", "Action"].map((h) => (
                  <th key={h} className="text-left px-5 py-3 font-medium">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {items.map((r) => (
                <tr key={r.id} className="hover:bg-slate-50 transition-colors">
                  <td className="px-5 py-3.5 text-sm font-medium text-slate-800">{r.account}</td>
                  <td className="px-5 py-3.5 text-sm text-slate-600 break-all">{r.email}</td>
                  <td className="px-5 py-3.5 text-sm text-slate-600">{ROLE_LABEL[r.role]}</td>
                  <td className="px-5 py-3.5 text-sm text-slate-500 whitespace-nowrap">{shortDate(r.created_at)}</td>
                  <td className="px-5 py-3.5">
                    <button onClick={() => { setNotice(""); setNote(""); setOpen(r); }} className="text-[#1e3a5f] text-sm font-medium hover:underline">
                      Review
                    </button>
                  </td>
                </tr>
              ))}
              {items.length === 0 && (
                <tr>
                  <td colSpan={5} className="px-5 py-10 text-center text-slate-400 text-sm">
                    {loading ? "Loading…" : "No password reset requests."}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {open && (
        <Modal
          title="Password reset request"
          subtitle={`${ROLE_LABEL[open.role]}: ${open.account}`}
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
              <p className="text-slate-500 text-xs mb-1">Send the new password to</p>
              <p className="font-medium text-slate-800 break-all">{open.email}</p>
            </div>
            <p className="text-xs text-slate-500">
              If you approve, their current password stops working now, they are signed out everywhere, and a random temporary password is
              emailed to this address. Check with the person first if you are not sure the request is really theirs.
            </p>
            <div>
              <label htmlFor="pr-note" className="block text-sm font-medium text-slate-700 mb-1.5">
                Note <span className="text-slate-400 font-normal">(optional)</span>
              </label>
              <textarea id="pr-note" value={note} maxLength={1000} onChange={(e) => setNote(e.target.value)} rows={3}
                        className="w-full px-3.5 py-2.5 border border-slate-300 rounded-lg text-sm placeholder-slate-400 focus:outline-none focus:border-[#1e3a5f] focus:ring-2 focus:ring-[#1e3a5f]/10 resize-none" />
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
}
