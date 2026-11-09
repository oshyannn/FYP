import { useState } from "react";
import { api, problem } from "../../../api";
import Modal from "../../../components/Modal";
import { Alert } from "../../../components/ui";

interface Props {
  onClose: () => void;
  /** an invitation was created: the lists reload */
  onCreated: () => void;
  onSessionEnd: () => void;
}

const empty = { full_name: "", email: "", email2: "", role: "employer" };

const fieldCls = (bad: boolean) =>
  `w-full px-3.5 py-2.5 border rounded-lg text-sm placeholder-slate-400 focus:outline-none focus:ring-2 transition-colors ${
    bad ? "border-red-400 focus:border-red-400 focus:ring-red-100" : "border-slate-300 focus:border-[#1e3a5f] focus:ring-[#1e3a5f]/10"
  }`;

// Administrator: invite an employer or an administrator. The invited person sets their own password with an emailed
// code; nothing is created until they do. An administrator invitation also waits for ANOTHER administrator's approval
// and comes with a PIN that is shown here once.
export default function CreateAccountModal({ onClose, onCreated, onSessionEnd }: Props) {
  const [form, setForm] = useState(empty);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState<{ role: string; email: string; name: string; pin?: string } | null>(null);
  const [copied, setCopied] = useState(false);

  const set = (k: keyof typeof empty, v: string) => {
    setForm((f) => ({ ...f, [k]: v }));
    setErrors((e) => ({ ...e, [k]: "" }));
  };

  async function submit() {
    if (busy) return;
    const e: Record<string, string> = {};
    if (form.full_name.trim().length < 2) e.full_name = "Enter the full name.";
    if (!form.email.trim()) e.email = "Enter the email address.";
    if (form.email.trim().toLowerCase() !== form.email2.trim().toLowerCase()) e.email2 = "The two email addresses do not match.";
    setErrors(e);
    if (Object.keys(e).length) return;
    setBusy(true);
    setError("");
    const res = await api.post("/api/staff/invitations", { full_name: form.full_name.trim(), email: form.email.trim(), role: form.role });
    setBusy(false);
    if (res.status === 401) return onSessionEnd();
    if (res.status === 201) {
      setDone({ role: form.role, email: res.data.invitation.email, name: res.data.invitation.full_name, pin: res.data.pin });
      onCreated();
      return;
    }
    const p = problem(res);
    if (Object.keys(p.fields).length) setErrors(p.fields);
    else setError(res.status === 429 ? "Too many invitations. Wait a while and try again." : p.message);
  }

  async function copyPin() {
    if (!done?.pin) return;
    try {
      await navigator.clipboard.writeText(done.pin);
      setCopied(true);
    } catch {
      setCopied(false);
    }
  }

  if (done) {
    return (
      <Modal
        title={done.pin ? "Waiting for approval" : "Invitation sent"}
        onClose={onClose}
        footer={
          <button onClick={onClose} className="w-full bg-[#1e3a5f] text-white py-2.5 rounded-lg text-sm font-semibold hover:bg-[#162d4a]">
            Done
          </button>
        }
      >
        {done.pin ? (
          <div className="space-y-4 text-sm text-slate-600">
            <p>
              The invitation for <b className="text-slate-800 break-all">{done.email}</b> as an <b>administrator</b> is waiting for{" "}
              <b>another administrator</b> to approve it. Nothing is emailed until then.
            </p>
            <div className="bg-amber-50 border border-amber-200 rounded-xl p-4 text-center">
              <p className="text-xs text-amber-800 mb-1">PIN for {done.name}</p>
              <p className="text-3xl font-bold tracking-widest text-amber-900">{done.pin}</p>
              <button onClick={copyPin} className="mt-2 text-xs font-medium text-amber-800 hover:underline">
                {copied ? "Copied" : "Copy PIN"}
              </button>
            </div>
            <p className="text-xs text-slate-500">
              <b>This PIN is shown only once.</b> Tell it to {done.name} by phone or chat, never by email. To activate the account they need the
              emailed code <i>and</i> this PIN. If you lose it, revoke the invitation and make a new one.
            </p>
          </div>
        ) : (
          <p className="text-sm text-slate-600">
            An email with a 6-digit code was sent to <b className="text-slate-800 break-all">{done.email}</b>. {done.name} has 24 hours to open the app,
            choose <b>Staff login → Activate your account</b> and set a password. You can follow it in the <b>Invitations</b> tab.
          </p>
        )}
      </Modal>
    );
  }

  return (
    <Modal
      title="Create Account"
      subtitle="Invite an employer or an administrator by email."
      onClose={onClose}
      footer={
        <>
          <button onClick={onClose} className="flex-1 border border-slate-300 text-slate-700 py-2.5 rounded-lg text-sm font-medium hover:bg-slate-50">
            Cancel
          </button>
          <button onClick={submit} disabled={busy} className="flex-1 bg-[#1e3a5f] text-white py-2.5 rounded-lg text-sm font-semibold hover:bg-[#162d4a] disabled:opacity-60">
            {busy ? "Checking…" : form.role === "admin" ? "Request invitation" : "Send invitation"}
          </button>
        </>
      }
    >
      {error && <Alert kind="error">{error}</Alert>}
      <div className="space-y-4">
        <div>
          <label htmlFor="ca-name" className="block text-sm font-medium text-slate-700 mb-1.5">Full name</label>
          <input id="ca-name" value={form.full_name} maxLength={100} onChange={(e) => set("full_name", e.target.value)} className={fieldCls(!!errors.full_name)} />
          {errors.full_name && <p className="text-red-500 text-xs mt-1">{errors.full_name}</p>}
        </div>
        <div>
          <label htmlFor="ca-email" className="block text-sm font-medium text-slate-700 mb-1.5">Email</label>
          <input id="ca-email" type="email" value={form.email} maxLength={254} autoComplete="off" onChange={(e) => set("email", e.target.value)} className={fieldCls(!!errors.email)} />
          {errors.email && <p className="text-red-500 text-xs mt-1">{errors.email}</p>}
        </div>
        <div>
          <label htmlFor="ca-email2" className="block text-sm font-medium text-slate-700 mb-1.5">Repeat email</label>
          <input id="ca-email2" type="email" value={form.email2} maxLength={254} autoComplete="off" onChange={(e) => set("email2", e.target.value)} onPaste={(e) => e.preventDefault()} className={fieldCls(!!errors.email2)} />
          {errors.email2 ? <p className="text-red-500 text-xs mt-1">{errors.email2}</p> : <p className="text-slate-400 text-xs mt-1">Type it again, do not paste: a mistyped address would send the invitation to a stranger.</p>}
        </div>
        <div>
          <label htmlFor="ca-role" className="block text-sm font-medium text-slate-700 mb-1.5">Role</label>
          <select id="ca-role" value={form.role} onChange={(e) => set("role", e.target.value)} className="w-full px-3.5 py-2.5 border border-slate-300 rounded-lg text-sm bg-white text-slate-700 focus:outline-none focus:border-[#1e3a5f]">
            <option value="employer">Employer</option>
            <option value="admin">Administrator</option>
          </select>
          {errors.role && <p className="text-red-500 text-xs mt-1">{errors.role}</p>}
        </div>
        <p className="text-xs text-slate-500 bg-slate-50 border border-slate-200 rounded-lg p-3">
          {form.role === "admin"
            ? "An administrator account is powerful, so it needs two things: another administrator must approve the invitation, and you will get a PIN to tell the person yourself. Nothing is emailed before the approval."
            : "The person gets an email with a 6-digit code and sets their own password. You never see or choose it. The code works for 24 hours."}
        </p>
      </div>
    </Modal>
  );
}
