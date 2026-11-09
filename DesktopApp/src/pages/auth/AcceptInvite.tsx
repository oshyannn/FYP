import { useState } from "react";
import type { FormEvent } from "react";
import AuthShell from "../../components/AuthShell";
import { Field, PasswordField } from "../../components/Field";
import { Alert, LinkButton, PrimaryButton, SecondaryButton } from "../../components/ui";
import { api, problem } from "../../api";
import type { Flow, Screen } from "../../types";

interface Props {
  go: (screen: Screen, flow?: Flow) => void;
}

// An administrator invited this person as an employer or an administrator. The account is created here, with the
// person's own password, once the emailed code (and, for an administrator, the PIN they were told) is right.
export default function AcceptInvite({ go }: Props) {
  const [email, setEmail] = useState("");
  const [code, setCode] = useState("");
  const [pin, setPin] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [fields, setFields] = useState<Record<string, string>>({});
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (busy) return;
    setError("");
    const f: Record<string, string> = {};
    if (!email.trim()) f.email = "Enter the email address you were invited with.";
    if (!/^\d{6}$/.test(code)) f.code = "Enter the 6-digit code from the email.";
    if (pin && !/^\d{6}$/.test(pin)) f.pin = "The PIN is 6 digits.";
    if (!password) f.password = "Choose a password.";
    else if (password !== confirm) f.confirm = "Passwords do not match.";
    setFields(f);
    if (Object.keys(f).length) return;

    setBusy(true);
    const res = await api.post("/api/staff/accept-invite", { email: email.trim(), code, pin, password });
    setBusy(false);
    if (res.status === 200) {
      go("staff-login", { email: email.trim(), portal: "staff", notice: "Your account is ready. Sign in with your email and your new password." });
      return;
    }
    const p = problem(res);
    if (p.fields.password) setFields({ password: p.fields.password });
    else setError(res.status === 429 ? "Too many attempts. Wait a while and try again." : p.message);
  }

  return (
    <AuthShell
      portal="staff"
      title="Activate your account"
      subtitle="Use the invitation an administrator sent you"
      footer={<LinkButton onClick={() => go("staff-login")}>← Back to staff login</LinkButton>}
    >
      {error && <Alert kind="error">{error}</Alert>}
      <form onSubmit={submit} className="space-y-4" noValidate>
        <Field label="Email" name="email" type="email" autoComplete="username" placeholder="name@company.com"
               value={email} onChange={(e) => setEmail(e.target.value)} error={fields.email} />
        <Field label="Invitation code" name="code" inputMode="numeric" autoComplete="one-time-code" maxLength={6}
               placeholder="123456" value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))} error={fields.code} />
        <div>
          <Field label="Administrator PIN (administrators only)" name="pin" inputMode="numeric" autoComplete="off" maxLength={6}
                 placeholder="Only if you were given one" value={pin} onChange={(e) => setPin(e.target.value.replace(/\D/g, ""))} error={fields.pin} />
          <p className="mt-1 text-xs text-slate-400">The PIN is not in the email. The person who invited you tells it to you by phone or chat.</p>
        </div>
        <PasswordField label="New password" name="password" autoComplete="new-password" placeholder="At least 10 characters"
                       value={password} onChange={(e) => setPassword(e.target.value)} error={fields.password} />
        <PasswordField label="Confirm password" name="confirm" autoComplete="new-password" placeholder="Repeat your password"
                       value={confirm} onChange={(e) => setConfirm(e.target.value)} error={fields.confirm} />
        <PrimaryButton type="submit" busy={busy} staff>Activate account</PrimaryButton>
        <SecondaryButton type="button" onClick={() => go("staff-login")}>Back to Login</SecondaryButton>
      </form>
    </AuthShell>
  );
}
