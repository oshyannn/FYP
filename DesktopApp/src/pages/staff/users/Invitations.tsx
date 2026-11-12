import { useCallback, useEffect, useState } from "react";
import { api, problem } from "../../../api";
import Badge from "../../../components/Badge";
import ConfirmDialog from "../../../components/ConfirmDialog";
import Pager from "../../../components/Pager";
import { Alert } from "../../../components/ui";
import { inviteLabel, inviteTone, roleLabel, roleTone, USERS_PER_PAGE } from "../../../lib/admin";
import type { Invitation } from "../../../lib/admin";
import { shortDate, shortDateTime } from "../../../lib/approvals";

interface Props {
  /** changes when something was created elsewhere, so the list reloads */
  reloadKey: number;
  onChanged: () => void;
  onSessionEnd: () => void;
}

const STATUSES: [string, string][] = [
  ["", "All Status"],
  ["awaiting_approval", "Awaiting approval"],
  ["sent", "Sent"],
  ["accepted", "Accepted"],
  ["revoked", "Revoked"],
  ["rejected", "Rejected"],
  ["expired", "Expired"],
  ["locked", "Locked"],
];

// Administrator: every invitation, whether it was accepted and when. An open one can be revoked.
export default function Invitations({ reloadKey, onChanged, onSessionEnd }: Props) {
  const [status, setStatus] = useState("");
  const [page, setPage] = useState(1);
  const [rows, setRows] = useState<Invitation[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [revoke, setRevoke] = useState<Invitation | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    const qs = new URLSearchParams({ page: String(page), per_page: String(USERS_PER_PAGE) });
    if (status) qs.set("status", status);
    const res = await api.get(`/api/staff/invitations?${qs.toString()}`);
    setLoading(false);
    if (res.status === 401) return onSessionEnd();
    if (res.status !== 200) return setError(problem(res).message);
    setError("");
    setRows(res.data.invitations as Invitation[]);
    setTotal(res.data.total as number);
  }, [status, page, reloadKey]);

  useEffect(() => {
    load();
  }, [load]);

  async function doRevoke() {
    if (!revoke || busy) return;
    setBusy(true);
    const res = await api.post(`/api/staff/invitations/${revoke.id}/revoke`);
    setBusy(false);
    if (res.status === 401) return onSessionEnd();
    const email = revoke.email;
    setRevoke(null);
    if (res.status === 200) setNotice(`The invitation for ${email} was revoked. Its code no longer works.`);
    else setError(problem(res).message);
    load();
    onChanged();
  }

  return (
    <div className="space-y-4">
      {error && <Alert kind="error">{error}</Alert>}
      {notice && <Alert kind="success">{notice}</Alert>}

      <div className="flex">
        <select
          value={status}
          onChange={(e) => {
            setStatus(e.target.value);
            setPage(1);
          }}
          aria-label="Filter by status"
          className="px-3.5 py-2 border border-slate-300 rounded-lg text-sm bg-white text-slate-700 focus:outline-none focus:border-[#1e3a5f]"
        >
          {STATUSES.map(([v, l]) => (
            <option key={v} value={v}>
              {l}
            </option>
          ))}
        </select>
      </div>

      <div className="bg-white rounded-xl border border-slate-200 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="text-xs text-slate-500 bg-slate-50 border-b border-slate-200">
                {["Person", "Role", "Status", "Invited by", "Date", "Action"].map((h) => (
                  <th key={h} className="text-left px-5 py-3 font-medium">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {rows.map((r) => (
                <tr key={r.id} className="hover:bg-slate-50 transition-colors">
                  <td className="px-5 py-3.5">
                    <div className="text-sm font-medium text-slate-800">{r.full_name}</div>
                    <div className="text-xs text-slate-500 break-all">{r.email}</div>
                  </td>
                  <td className="px-5 py-3.5">
                    <Badge tone={roleTone(r.role)}>{roleLabel(r.role)}</Badge>
                  </td>
                  <td className="px-5 py-3.5">
                    <Badge tone={inviteTone(r.status)}>{inviteLabel(r.status)}</Badge>
                    {r.status === "accepted" && r.accepted_at && <div className="text-xs text-slate-500 mt-1">{shortDateTime(r.accepted_at)}</div>}
                    {r.status === "sent" && r.expires_at && <div className="text-xs text-slate-400 mt-1">until {shortDateTime(r.expires_at)}</div>}
                  </td>
                  <td className="px-5 py-3.5 text-sm text-slate-600">{r.invited_by}</td>
                  <td className="px-5 py-3.5 text-sm text-slate-500 whitespace-nowrap">{shortDate(r.created_at)}</td>
                  <td className="px-5 py-3.5">
                    {r.status === "awaiting_approval" || r.status === "sent" ? (
                      <button onClick={() => { setNotice(""); setRevoke(r); }} className="text-red-500 text-sm font-medium hover:underline">
                        Revoke
                      </button>
                    ) : (
                      <span className="text-slate-300">—</span>
                    )}
                  </td>
                </tr>
              ))}
              {rows.length === 0 && (
                <tr>
                  <td colSpan={6} className="px-5 py-10 text-center text-slate-400 text-sm">
                    {loading ? "Loading…" : "No invitations yet. Use Create Account to invite an employer or an administrator."}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
        <Pager page={page} perPage={USERS_PER_PAGE} total={total} onPage={setPage} />
      </div>

      {revoke && (
        <ConfirmDialog title="Revoke invitation?" tone="red" confirmLabel="Revoke" busy={busy} onConfirm={doRevoke} onCancel={() => setRevoke(null)}>
          <p className="font-medium text-slate-700 mb-1 break-all">{revoke.email}</p>
          <p>The code stops working at once. The person cannot create an account from this invitation.</p>
        </ConfirmDialog>
      )}
    </div>
  );
}
