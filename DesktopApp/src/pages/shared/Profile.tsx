import { useEffect, useState } from "react";
import type { FormEvent } from "react";
import { api, problem } from "../../api";
import { Field, PasswordField } from "../../components/Field";
import { Alert } from "../../components/ui";

interface ProfileData {
  id: string;
  email: string;
  full_name: string | null;
  role: "user" | "employer" | "admin";
  email_verified: boolean;
  status: string;
  created_at: string;
  last_login_at: string | null;
}

interface Props {
  onSessionEnd: () => void;
  /** tells the app the display name changed (sidebar / header) */
  onNameChanged: (name: string) => void;
}

const ROLE_LABEL = { user: "User", employer: "Employer", admin: "Administrator" } as const;
const STATUS_LABEL: Record<string, string> = { active: "Active", pending: "Pending", suspended: "Suspended", deleted: "Deleted" };

function initials(name: string) {
  const parts = name.trim().split(/\s+/).filter(Boolean);
  return ((parts[0]?.[0] ?? "?") + (parts.length > 1 ? parts[parts.length - 1][0] : "")).toUpperCase();
}

export default function Profile({ onSessionEnd, onNameChanged }: Props) {
  const [p, setP] = useState<ProfileData | null>(null);
  const [error, setError] = useState("");
  const [done, setDone] = useState("");
  const [modal, setModal] = useState<"" | "name" | "password">("");
  const [busy, setBusy] = useState(false);
  const [fields, setFields] = useState<Record<string, string>>({});
  const [name, setName] = useState("");
  const [cur, setCur] = useState("");
  const [next, setNext] = useState("");
  const [again, setAgain] = useState("");

  useEffect(() => {
    (async () => {
      const res = await api.get("/api/me/profile");
      if (res.status === 401) return onSessionEnd();
      if (res.status === 200) setP(res.data.profile as ProfileData);
      else setError(problem(res).message);
    })();
  }, []);

  function openModal(m: "name" | "password") {
    setFields({});
    setError("");
    setDone("");
    setName(p?.full_name ?? "");
    setCur("");
    setNext("");
    setAgain("");
    setModal(m);
  }

  async function saveName(e: FormEvent) {
    e.preventDefault();
    if (busy || !p) return;
    if (name.trim().length < 2) return setFields({ full_name: "Enter your full name." });
    setBusy(true);
    const res = await api.patch("/api/me", { full_name: name.trim() });
    setBusy(false);
    if (res.status === 401) return onSessionEnd();
    if (res.status === 200) {
      const saved = res.data.user.full_name as string;
      setP({ ...p, full_name: saved });
      onNameChanged(saved);
      setModal("");
      setDone("Your profile was updated.");
    } else setFields(problem(res).fields);
  }

  async function savePassword(e: FormEvent) {
    e.preventDefault();
    if (busy) return;
    if (!cur) return setFields({ current: "Enter your current password." });
    if (next !== again) return setFields({ again: "Passwords do not match." });
    setBusy(true);
    const res = await api.post("/api/me/password", { current_password: cur, new_password: next });
    setBusy(false);
    if (res.status === 401) return onSessionEnd();
    if (res.status === 200) {
      setModal("");
      setDone("Password updated. You were signed out on your other devices.");
      return;
    }
    const pr = problem(res);
    if (pr.fields.new_password) setFields({ next: pr.fields.new_password });
    else if (res.data?.error?.code === "invalid_credentials") setFields({ current: pr.message });
    else setError(pr.message);
  }

  const display = p?.full_name ?? p?.email ?? "";
  const rows: [string, string][] = p
    ? [
        ["Full Name", p.full_name ?? "—"],
        ["Email", p.email],
        ["Account Type", ROLE_LABEL[p.role]],
        ["Email Verification", p.email_verified ? "Verified ✓" : "Not verified"],
        ["Account Status", STATUS_LABEL[p.status] ?? p.status],
        ["Member since", new Date(p.created_at).toLocaleDateString()],
        ["Last login", p.last_login_at ? new Date(p.last_login_at).toLocaleString() : "—"],
      ]
    : [];

  return (
    <div className="max-w-xl space-y-5">
      <h2 className="text-xl font-bold text-slate-900">Profile</h2>
      {error && <Alert kind="error">{error}</Alert>}
      {done && <Alert kind="success">{done}</Alert>}

      <div className="bg-white rounded-xl border border-slate-200 p-6">
        {!p ? (
          <p className="text-sm text-slate-400">Loading…</p>
        ) : (
          <>
            <div className="flex items-center gap-5 mb-6">
              <div className="w-16 h-16 rounded-2xl bg-[#1e3a5f] text-white text-xl font-bold flex items-center justify-center" aria-hidden="true">
                {initials(display)}
              </div>
              <div className="min-w-0">
                <div className="font-semibold text-slate-900 text-lg truncate">{display}</div>
                <div className="text-slate-500 text-sm truncate">{p.email}</div>
              </div>
            </div>
            <div className="divide-y divide-slate-100 mb-5">
              {rows.map(([l, v]) => (
                <div key={l} className="flex justify-between gap-4 py-3 text-sm">
                  <span className="text-slate-500 shrink-0">{l}</span>
                  <span className="text-slate-800 font-medium text-right break-all">{v}</span>
                </div>
              ))}
            </div>
            <div className="flex gap-3">
              <button onClick={() => openModal("name")} className="bg-[#1e3a5f] text-white px-5 py-2.5 rounded-lg text-sm font-semibold hover:bg-[#162d4a] transition-colors">
                Edit Profile
              </button>
              <button onClick={() => openModal("password")} className="border border-slate-300 text-slate-700 px-5 py-2.5 rounded-lg text-sm font-medium hover:bg-slate-50 transition-colors">
                Change Password
              </button>
            </div>
            <p className="text-xs text-slate-400 mt-4">Your email address is also your login and cannot be changed here.</p>
          </>
        )}
      </div>

      {modal === "name" && (
        <div className="fixed inset-0 z-50 bg-black/40 flex items-center justify-center p-4" role="dialog" aria-modal="true" aria-labelledby="pf-name">
          <form onSubmit={saveName} noValidate className="bg-white rounded-2xl p-6 max-w-sm w-full shadow-xl space-y-4">
            <h3 id="pf-name" className="font-semibold text-slate-900">Edit Profile</h3>
            <Field label="Full Name" name="full_name" autoComplete="name" value={name} maxLength={100} onChange={(e) => setName(e.target.value)} error={fields.full_name} />
            <div className="flex gap-3">
              <button type="button" onClick={() => setModal("")} className="flex-1 border border-slate-300 text-slate-700 py-2.5 rounded-lg text-sm font-medium hover:bg-slate-50">Cancel</button>
              <button type="submit" disabled={busy} className="flex-1 bg-[#1e3a5f] text-white py-2.5 rounded-lg text-sm font-semibold hover:bg-[#162d4a] disabled:opacity-60">{busy ? "Saving…" : "Save"}</button>
            </div>
          </form>
        </div>
      )}

      {modal === "password" && (
        <div className="fixed inset-0 z-50 bg-black/40 flex items-center justify-center p-4" role="dialog" aria-modal="true" aria-labelledby="pf-pw">
          <form onSubmit={savePassword} noValidate className="bg-white rounded-2xl p-6 max-w-sm w-full shadow-xl space-y-4">
            <h3 id="pf-pw" className="font-semibold text-slate-900">Change Password</h3>
            {error && <Alert kind="error">{error}</Alert>}
            <PasswordField label="Current password" name="current" autoComplete="current-password" value={cur} onChange={(e) => setCur(e.target.value)} error={fields.current} />
            <PasswordField label="New password" name="next" autoComplete="new-password" placeholder="At least 10 characters" value={next} onChange={(e) => setNext(e.target.value)} error={fields.next} />
            <PasswordField label="Confirm new password" name="again" autoComplete="new-password" value={again} onChange={(e) => setAgain(e.target.value)} error={fields.again} />
            <div className="flex gap-3">
              <button type="button" onClick={() => setModal("")} className="flex-1 border border-slate-300 text-slate-700 py-2.5 rounded-lg text-sm font-medium hover:bg-slate-50">Cancel</button>
              <button type="submit" disabled={busy} className="flex-1 bg-[#1e3a5f] text-white py-2.5 rounded-lg text-sm font-semibold hover:bg-[#162d4a] disabled:opacity-60">{busy ? "Saving…" : "Update password"}</button>
            </div>
          </form>
        </div>
      )}
    </div>
  );
}
