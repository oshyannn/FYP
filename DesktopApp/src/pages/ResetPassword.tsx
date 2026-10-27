import { useState } from "react";
import type { FormEvent } from "react";
import AuthShell from "../components/AuthShell";
import { Field, PasswordField } from "../components/Field";
import { Alert, PrimaryButton, SecondaryButton } from "../components/ui";
import { api, problem } from "../api";
import type { Flow, Screen } from "../types";

interface Props {
  flow: Flow;
  go: (screen: Screen, flow?: Flow) => void;
}

export default function ResetPassword({ flow, go }: Props) {
  const [code, setCode] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [fields, setFields] = useState<Record<string, string>>({});
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const staff = flow.portal === "staff";

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (busy) return;
    setError("");
    if (!/^\d{6}$/.test(code)) {
      setFields({ code: "Enter the 6-digit code from the email." });
      return;
    }
    if (password !== confirm) {
      setFields({ confirm: "Passwords do not match." });
      return;
    }
    setFields({});
    setBusy(true);
    const res = await api.post("/api/auth/reset-password", { email: flow.email, code, new_password: password });
    setBusy(false);
    if (res.status === 200) {
      go(staff ? "staff-login" : "user-login", {
        email: flow.email,
        portal: flow.portal,
        notice: "Password updated. Log in with your new password.",
      });
      return;
    }
    const p = problem(res);
    if (p.fields.new_password) setFields({ password: p.fields.new_password });
    else setError(p.message);
  }

  return (
    <AuthShell portal={flow.portal} title="Choose a new password" subtitle={flow.email}>
      {error && <Alert kind="error">{error}</Alert>}
      <form onSubmit={submit} className="space-y-4" noValidate>
        <Field label="Reset code" name="code" inputMode="numeric" autoComplete="one-time-code" maxLength={6}
               placeholder="123456" value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))} error={fields.code} />
        <PasswordField label="New password" name="password" autoComplete="new-password" placeholder="At least 10 characters"
                       value={password} onChange={(e) => setPassword(e.target.value)} error={fields.password} />
        <PasswordField label="Confirm password" name="confirm" autoComplete="new-password" placeholder="Repeat your password"
                       value={confirm} onChange={(e) => setConfirm(e.target.value)} error={fields.confirm} />
        <PrimaryButton type="submit" busy={busy} staff={staff}>Update Password</PrimaryButton>
        <SecondaryButton type="button" onClick={() => go(staff ? "staff-login" : "user-login")}>Back to Login</SecondaryButton>
      </form>
    </AuthShell>
  );
}
