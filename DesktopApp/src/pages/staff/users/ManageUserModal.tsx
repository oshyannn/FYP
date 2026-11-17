import { useEffect, useState } from "react";
import { api, problem } from "../../../api";
import Badge from "../../../components/Badge";
import ConfirmDialog from "../../../components/ConfirmDialog";
import Modal from "../../../components/Modal";
import { Alert } from "../../../components/ui";
import { shortDate, shortDateTime } from "../../../lib/approvals";
import { accountStatusLabel, accountStatusTone, displayName, roleLabel } from "../../../lib/admin";
import type { AdminUser, StaffRole } from "../../../lib/admin";

interface Props {
  user: AdminUser;
  actorRole: StaffRole;
  onClose: () => void;
  /** the account changed: the list reloads and shows the message */
  onChanged: (message: string) => void;
  onSessionEnd: () => void;
}

type Mode = "manage" | "view" | "edit";
type Confirm = "deactivate" | "activate" | "reset" | null;
type RequestAction = "deactivate" | "activate";

const REQUEST_TEXT: Record<RequestAction, [string, string]> = {
  deactivate: ["Request deactivation", "The administrator will be signed out everywhere and cannot sign in, once a third administrator approves."],
  activate: ["Request activation", "The administrator can sign in again, once a third administrator approves."],
};

const btn = "w-full border border-slate-300 text-slate-700 py-2.5 rounded-lg text-sm font-medium hover:bg-slate-50";

/** Why there is nothing (or little) to press, in words. */
function explain(u: AdminUser): string | null {
  if (u.status === "deleted") return "This account was deleted. It is kept for the records and cannot be changed.";
  if (u.is_self) return "This is your own account. Change your details in Profile.";
  if (u.role === "admin") {
    return u.pending_change
      ? `A request to ${u.pending_change.action} this account is waiting for a third administrator (asked by ${u.pending_change.requested_by}).`
      : "Another administrator's account cannot be changed directly. Send a request: a third administrator has to approve it.";
  }
  if (u.status === "pending") return "This account is pending. It becomes active when the email is verified.";
  return null;
}

// The "Manage User" card. What it offers comes from the server (user.actions), never from the screen's own rules.
export default function ManageUserModal({ user, actorRole, onClose, onChanged, onSessionEnd }: Props) {
  const isEmployer = actorRole === "employer";
  const [u, setU] = useState<AdminUser>(user);
  const [mode, setMode] = useState<Mode>("manage");
  const [detail, setDetail] = useState<AdminUser | null>(null);
  const [name, setName] = useState(user.full_name ?? "");
  const [nameError, setNameError] = useState("");
  const [reason, setReason] = useState("");
  const [reasonError, setReasonError] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [confirm, setConfirm] = useState<Confirm>(null);
  const [requestAction, setRequestAction] = useState<RequestAction | null>(null);

  useEffect(() => {
    if (mode !== "view" || detail) return;
    api.get(`/api/staff/users/${u.id}`).then((res) => {
      if (res.status === 401) onSessionEnd();
      else if (res.status === 200) setDetail(res.data.user as AdminUser);
      else setError(problem(res).message);
    });
  }, [mode]);

  async function saveName() {
    const value = name.trim().replace(/\s+/g, " ");
    if (value.length < 2) return setNameError("Enter the full name.");
    const r = reason.trim();
    if (isEmployer && r.length < 3) return setReasonError("Please enter a reason (at least 3 characters).");
    setBusy(true);
    setError("");
    const res = await api.patch(`/api/staff/users/${u.id}`, isEmployer ? { full_name: value, reason: r } : { full_name: value });
    setBusy(false);
    if (res.status === 401) return onSessionEnd();
    if (res.status === 200) {
      const next = res.data.user as AdminUser;
      setU(next);
      setDetail(null);
      setReason("");
      setMode("manage");
      onChanged(`${displayName(next)} was updated.`);
      return;
    }
    const p = problem(res);
    if (p.fields.full_name) setNameError(p.fields.full_name);
    else if (p.fields.reason) setReasonError(p.fields.reason);
    else setError(p.message);
  }

  async function sendRequest(action: RequestAction) {
    const r = reason.trim();
    if (isEmployer && r.length < 3) {
      setReasonError("Please enter a reason (at least 3 characters).");
      return;
    }
    setBusy(true);
    setError("");
    setRequestAction(null);
    const res = await api.post("/api/staff/admin-changes", {
      user_id: u.id,
      action,
      ...(isEmployer ? { reason: r } : {}),
    });
    setBusy(false);
    if (res.status === 401) return onSessionEnd();
    if (res.status !== 201) return setError(problem(res).message);
    onChanged(`Your request to ${action} ${displayName(u)} was sent. An administrator has to approve it; nothing changes until then.`);
    onClose();
  }

  async function resetPassword() {
    const r = reason.trim();
    if (isEmployer && r.length < 3) {
      setReasonError("Please enter a reason (at least 3 characters).");
      return;
    }
    setBusy(true);
    setError("");
    setConfirm(null);
    const res = await api.post(`/api/staff/users/${u.id}/password-reset`, isEmployer ? { reason: r } : undefined);
    setBusy(false);
    if (res.status === 401) return onSessionEnd();
    if (res.status === 201) {
      onChanged(`A password reset request for ${displayName(u)} was sent. Nothing changes until another person approves it.`);
      onClose();
      return;
    }
    if (res.status !== 200) return setError(problem(res).message);
    onChanged(`${displayName(u)}'s password was reset. A temporary password was emailed to ${res.data.email}.`);
    onClose();
  }

  async function run(kind: "deactivate" | "activate") {
    const r = reason.trim();
    if (isEmployer && r.length < 3) {
      setReasonError("Please enter a reason (at least 3 characters).");
      return;
    }
    setBusy(true);
    setError("");
    setConfirm(null);
    const who = displayName(u);
    const res = await api.post(`/api/staff/users/${u.id}/status`, {
      status: kind === "activate" ? "active" : "inactive",
      ...(isEmployer ? { reason: r } : {}),
    });
    setBusy(false);
    if (res.status === 401) return onSessionEnd();
    if (res.status !== 200) return setError(problem(res).message);
    onChanged(`${who} was ${kind === "activate" ? "activated" : "deactivated"}.`);
    onClose();
  }

  const a = u.actions;
  const note = explain(u);
  const shown = mode === "view" && detail ? detail : u;
  const rows: [string, React.ReactNode][] = [
    ["Name", displayName(shown)],
    ["Email", shown.email],
    ["Role", roleLabel(shown.role)],
    ["Status", <Badge tone={accountStatusTone(shown.status)}>{accountStatusLabel(shown.status)}</Badge>],
    ...(mode === "view" && detail
      ? ([
          ["Email verified", detail.email_verified ? "Yes" : "No"],
          ["Registered", shortDate(detail.created_at)],
          ["Last sign-in", detail.last_login_at ? shortDateTime(detail.last_login_at) : "Never"],
          ["URL scans", String(detail.scan_count ?? 0)],
        ] as [string, React.ReactNode][])
      : []),
  ];

  return (
    <>
      <Modal title={mode === "edit" ? "Edit Account" : mode === "view" ? "Account Details" : "Manage User"} onClose={onClose}>
        {error && <Alert kind="error">{error}</Alert>}

        {mode === "edit" ? (
          <div className="space-y-4">
            <div>
              <label htmlFor="um-name" className="block text-sm font-medium text-slate-700 mb-1.5">
                Full name
              </label>
              <input
                id="um-name"
                value={name}
                maxLength={100}
                onChange={(e) => {
                  setName(e.target.value);
                  setNameError("");
                }}
                className={`w-full px-3.5 py-2.5 border rounded-lg text-sm focus:outline-none focus:ring-2 ${nameError ? "border-red-400 focus:ring-red-100" : "border-slate-300 focus:border-[#1e3a5f] focus:ring-[#1e3a5f]/10"}`}
              />
              {nameError && <p className="text-red-500 text-xs mt-1">{nameError}</p>}
              <p className="text-slate-400 text-xs mt-2">The email address and the role cannot be changed here.</p>
            </div>
            {isEmployer && (
              <div>
                <label htmlFor="um-reason" className="block text-sm font-medium text-slate-700 mb-1.5">
                  Reason for change <span className="text-red-500">*</span>
                </label>
                <textarea
                  id="um-reason"
                  value={reason}
                  maxLength={500}
                  rows={2}
                  onChange={(e) => {
                    setReason(e.target.value);
                    setReasonError("");
                  }}
                  placeholder="Why are you editing this account?"
                  className={`w-full px-3.5 py-2 border rounded-lg text-sm focus:outline-none focus:ring-2 resize-none ${reasonError ? "border-red-400 focus:ring-red-100" : "border-slate-300 focus:border-[#1e3a5f] focus:ring-[#1e3a5f]/10"}`}
                />
                {reasonError && <p className="text-red-500 text-xs mt-1">{reasonError}</p>}
              </div>
            )}
            <div className="flex gap-3">
              <button onClick={() => setMode("manage")} className="flex-1 border border-slate-300 text-slate-700 py-2.5 rounded-lg text-sm font-medium hover:bg-slate-50">
                Cancel
              </button>
              <button onClick={saveName} disabled={busy} className="flex-1 bg-[#1e3a5f] text-white py-2.5 rounded-lg text-sm font-semibold hover:bg-[#162d4a] disabled:opacity-60">
                {busy ? "Saving…" : "Save"}
              </button>
            </div>
          </div>
        ) : (
          <>
            <div className="divide-y divide-slate-100 text-sm">
              {rows.map(([l, v]) => (
                <div key={l} className="flex items-center justify-between py-2.5 gap-4">
                  <span className="text-slate-500">{l}</span>
                  <span className="text-slate-800 font-medium text-right break-all">{v}</span>
                </div>
              ))}
              {mode === "view" && !detail && !error && <p className="py-3 text-slate-400">Loading…</p>}
            </div>

            <div className="flex flex-col gap-2 pt-4">
              {mode === "manage" ? (
                <>
                  <button onClick={() => setMode("view")} className={btn}>
                    View Account
                  </button>
                  {a.edit && (
                    <button
                      onClick={() => {
                        setName(u.full_name ?? "");
                        setNameError("");
                        setReason("");
                        setReasonError("");
                        setMode("edit");
                      }}
                      className={btn}
                    >
                      Edit Account
                    </button>
                  )}
                  {a.reset_password && (
                    <button
                      onClick={() => {
                        setReason("");
                        setReasonError("");
                        setConfirm("reset");
                      }}
                      disabled={busy}
                      className={btn}
                    >
                      {a.reset_direct ? "Reset Password" : "Request Password Reset"}
                    </button>
                  )}
                  {note && <p className="text-xs text-slate-500 bg-slate-50 border border-slate-200 rounded-lg p-3">{note}</p>}
                  {a.deactivate && (
                    <button
                      onClick={() => {
                        setReason("");
                        setReasonError("");
                        setConfirm("deactivate");
                      }}
                      disabled={busy}
                      className="w-full py-2.5 rounded-lg text-sm font-semibold text-white bg-red-600 hover:bg-red-700 disabled:opacity-60"
                    >
                      Deactivate Account
                    </button>
                  )}
                  {a.activate && (
                    <button
                      onClick={() => {
                        if (isEmployer) {
                          setReason("");
                          setReasonError("");
                          setConfirm("activate");
                        } else {
                          run("activate");
                        }
                      }}
                      disabled={busy}
                      className="w-full py-2.5 rounded-lg text-sm font-semibold text-white bg-green-600 hover:bg-green-700 disabled:opacity-60"
                    >
                      {busy ? "Please wait…" : "Activate Account"}
                    </button>
                  )}
                  {(["deactivate", "activate"] as RequestAction[]).map((k) =>
                    a[`request_${k}` as "request_deactivate" | "request_activate"] ? (
                      <button
                        key={k}
                        onClick={() => {
                          setReason("");
                          setReasonError("");
                          setRequestAction(k);
                        }}
                        disabled={busy}
                        className={`w-full py-2.5 rounded-lg text-sm font-semibold border disabled:opacity-60 ${k === "activate" ? "text-green-700 border-green-300 hover:bg-green-50" : "text-red-600 border-red-300 hover:bg-red-50"}`}
                      >
                        {REQUEST_TEXT[k][0]}
                      </button>
                    ) : null,
                  )}
                  <button onClick={onClose} className={btn}>
                    Cancel
                  </button>
                </>
              ) : (
                <button onClick={() => setMode("manage")} className={btn}>
                  Back
                </button>
              )}
            </div>
          </>
        )}
      </Modal>

      {confirm === "deactivate" && (
        <ConfirmDialog title="Deactivate Account?" tone="red" confirmLabel="Deactivate" busy={busy} onConfirm={() => run("deactivate")} onCancel={() => setConfirm(null)}>
          <p className="font-medium text-slate-700 mb-1 break-all">{displayName(u)}</p>
          <p>They will be signed out everywhere (app and browser extension) and cannot sign in until the account is activated again.</p>
          {isEmployer && (
            <div className="mt-3 text-left">
              <label className="block text-xs font-medium text-slate-700 mb-1">Reason <span className="text-red-500">*</span></label>
              <textarea value={reason} maxLength={500} rows={2} onChange={(e) => { setReason(e.target.value); setReasonError(""); }} placeholder="Explain why you are deactivating this account..." className="w-full px-3 py-2 border border-slate-300 rounded-lg text-sm resize-none focus:outline-none focus:border-[#1e3a5f]" />
              {reasonError && <p className="text-red-500 text-xs mt-1">{reasonError}</p>}
            </div>
          )}
        </ConfirmDialog>
      )}
      {confirm === "activate" && (
        <ConfirmDialog title="Activate Account?" tone="green" confirmLabel="Activate" busy={busy} onConfirm={() => run("activate")} onCancel={() => setConfirm(null)}>
          <p className="font-medium text-slate-700 mb-1 break-all">{displayName(u)}</p>
          <p>They will be able to sign in again.</p>
          {isEmployer && (
            <div className="mt-3 text-left">
              <label className="block text-xs font-medium text-slate-700 mb-1">Reason <span className="text-red-500">*</span></label>
              <textarea value={reason} maxLength={500} rows={2} onChange={(e) => { setReason(e.target.value); setReasonError(""); }} placeholder="Explain why you are activating this account..." className="w-full px-3 py-2 border border-slate-300 rounded-lg text-sm resize-none focus:outline-none focus:border-[#1e3a5f]" />
              {reasonError && <p className="text-red-500 text-xs mt-1">{reasonError}</p>}
            </div>
          )}
        </ConfirmDialog>
      )}
      {requestAction && (
        <ConfirmDialog title={`${REQUEST_TEXT[requestAction][0]}?`} tone={requestAction === "activate" ? "green" : "red"} confirmLabel="Send request" busy={busy} onConfirm={() => sendRequest(requestAction)} onCancel={() => setRequestAction(null)}>
          <p className="font-medium text-slate-700 mb-1 break-all">{displayName(u)}</p>
          <p>
            {isEmployer
              ? "The user will be signed out everywhere and cannot sign in once an administrator approves. Nothing changes until then."
              : `${REQUEST_TEXT[requestAction][1]} Nothing changes until then. You cannot approve your own request.`}
          </p>
          {isEmployer && (
            <div className="mt-3 text-left">
              <label className="block text-xs font-medium text-slate-700 mb-1">Reason <span className="text-red-500">*</span></label>
              <textarea value={reason} maxLength={500} rows={2} onChange={(e) => { setReason(e.target.value); setReasonError(""); }} placeholder="Explain why you are requesting deactivation..." className="w-full px-3 py-2 border border-slate-300 rounded-lg text-sm resize-none focus:outline-none focus:border-[#1e3a5f]" />
              {reasonError && <p className="text-red-500 text-xs mt-1">{reasonError}</p>}
            </div>
          )}
        </ConfirmDialog>
      )}
            {confirm === "reset" && (
        <ConfirmDialog
          title={a.reset_direct ? "Reset Password Now?" : "Request Password Reset?"}
          tone="red"
          confirmLabel={a.reset_direct ? "Reset now" : "Send request"}
          busy={busy}
          onConfirm={resetPassword}
          onCancel={() => setConfirm(null)}
        >
          <p className="font-medium text-slate-700 mb-1 break-all">{u.email}</p>
          {a.reset_direct ? (
            <p className="font-medium text-red-600 mt-2">
              This changes the password immediately. The current password stops working and the person is signed out everywhere. A temporary
              password is emailed to them, and they must choose their own at the next sign-in. You will never see it.
            </p>
          ) : (
            <>
              <p>This sends a request to an administrator. Nothing changes until it is approved.</p>
              <p className="font-medium text-red-600 mt-2">
                If it is approved, the password changes immediately. The current password stops working, the person is signed out everywhere,
                and a temporary password is emailed to them. You will never see it.
              </p>
              <div className="mt-3 text-left">
                <label className="block text-xs font-medium text-slate-700 mb-1">Reason <span className="text-red-500">*</span></label>
                <textarea value={reason} maxLength={500} rows={2} onChange={(e) => { setReason(e.target.value); setReasonError(""); }} placeholder="Explain why you are requesting a password reset..." className="w-full px-3 py-2 border border-slate-300 rounded-lg text-sm resize-none focus:outline-none focus:border-[#1e3a5f]" />
                {reasonError && <p className="text-red-500 text-xs mt-1">{reasonError}</p>}
              </div>
            </>
          )}
        </ConfirmDialog>
      )}
    </>
  );
}
