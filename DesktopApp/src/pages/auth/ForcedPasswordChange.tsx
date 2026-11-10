import { useState } from "react";
import type { FormEvent } from "react";
import AuthShell from "../../components/AuthShell";
import { PasswordField } from "../../components/Field";
import { Alert, LinkButton, PrimaryButton } from "../../components/ui";
import { api, problem } from "../../api";
import type { Session, User } from "../../types";

interface Props {
  session: Session;
  /** the password was changed: the app continues with this (updated) user */
  onDone: (user: User) => void;
  onLogout: () => void;
}

// Shown INSTEAD of the app while the account has a temporary password (a new employer, or after an approved reset).
// The server enforces the same rule on every request, so this screen cannot be skipped by going around it.
export default function ForcedPasswordChange({ session, onDone, onLogout }: Props) {
  const staff = session.portal === "staff";
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [fields, setFields] = useState<Record<string, string>>({});
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (busy) return;
    if (password !== confirm) {
      setFields({ confirm: "Passwords do not match." });
      return;
    }
    setFields({});
    setError("");
    setBusy(true);
    const res = await api.post("/api/me/first-password", { new_password: password });
    setBusy(false);
    if (res.status === 200) {
      onDone(res.data.user as User);
      return;
    }
    if (res.status === 401) return onLogout();
    const p = problem(res);
    if (p.fields.new_password) setFields({ password: p.fields.new_password });
    else setError(res.status === 429 ? "Too many attempts. Wait a while and try again." : p.message);
  }

  async function logout() {
    await api.post("/api/auth/logout", {});
    onLogout();
  }

  return (
    <AuthShell
      portal={staff ? "staff" : "user"}
      title="Choose your own password"
      subtitle={`Signed in as ${session.user.email}`}
      footer={<LinkButton onClick={logout}>Log out</LinkButton>}
    >
      {error && <Alert kind="error">{error}</Alert>}
      <p className="text-sm text-slate-600 leading-relaxed mb-4">
        You signed in with a temporary password. Choose your own password now: nothing else in the app can be used until you do. This also
        confirms your email address.
      </p>
      <form onSubmit={submit} className="space-y-4" noValidate>
        <PasswordField label="New password" name="password" autoComplete="new-password" placeholder="At least 10 characters"
                       value={password} onChange={(e) => setPassword(e.target.value)} error={fields.password} />
        <PasswordField label="Confirm password" name="confirm" autoComplete="new-password" placeholder="Repeat your password"
                       value={confirm} onChange={(e) => setConfirm(e.target.value)} error={fields.confirm} />
        <PrimaryButton type="submit" busy={busy} staff={staff}>Save password and continue</PrimaryButton>
      </form>
    </AuthShell>
  );
}
