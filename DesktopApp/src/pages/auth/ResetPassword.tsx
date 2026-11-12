import { useState } from "react";
import type { FormEvent } from "react";
import AuthShell from "../../components/AuthShell";
import { Field, PasswordField } from "../../components/Field";
import { Alert, PrimaryButton, SecondaryButton } from "../../components/ui";
import { api, problem } from "../../api";
import type { Flow, Screen } from "../../types";

interface Props {
  flow: Flow;
  go: (screen: Screen, flow?: Flow) => void;
}

// The same two server calls as the "Forgot password" screen: the PIN is checked first (it returns a ticket), then the
// new password is sent with that ticket. An employer or administrator has no second step: the request waits for an
// administrator's approval and a temporary password is emailed afterwards.
type Step = "code" | "approval" | "password";

export default function ResetPassword({ flow, go }: Props) {
  const [step, setStep] = useState<Step>("code");
  const [code, setCode] = useState("");
  const [ticket, setTicket] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [fields, setFields] = useState<Record<string, string>>({});
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const staff = flow.portal === "staff";

  function back() {
    go(staff ? "staff-login" : "user-login");
  }

  // Step 1: check the PIN. Only when it is right do we ask for the new password.
  async function checkCode(e: FormEvent) {
    e.preventDefault();
    if (busy) return;
    setError("");
    if (!/^\d{6}$/.test(code)) {
      setFields({ code: "Enter the 6-digit code from the email." });
      return;
    }
    setFields({});
    setBusy(true);
    const res = await api.post("/api/auth/reset/verify", { email: flow.email, code });
    setBusy(false);
    if (res.status === 202 && res.data?.flow === "approval") {
      setStep("approval");
      return;
    }
    if (res.status === 200) {
      setTicket(res.data.ticket as string);
      setStep("password");
      return;
    }
    setFields({ code: problem(res).message });
  }

  // Step 2: the new password, together with the ticket from step 1.
  async function setNewPassword(e: FormEvent) {
    e.preventDefault();
    if (busy) return;
    setError("");
    if (password !== confirm) {
      setFields({ confirm: "Passwords do not match." });
      return;
    }
    setFields({});
    setBusy(true);
    const res = await api.post("/api/auth/reset/set-password", { email: flow.email, ticket, new_password: password });
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
    else if (res.status === 400 && p.message.includes("expired")) {
      setError(p.message);
      setCode("");
      setStep("code");
    } else setError(p.message);
  }

  const subtitle = step === "password" ? `Choose a new password for ${flow.email}` : step === "approval" ? "Request sent" : flow.email;

  return (
    <AuthShell portal={flow.portal} title="Choose a new password" subtitle={subtitle}>
      {error && <Alert kind="error">{error}</Alert>}

      {step === "code" && (
        <form onSubmit={checkCode} className="space-y-4" noValidate>
          <Field label="Reset code" name="code" inputMode="numeric" autoComplete="one-time-code" maxLength={6}
                 placeholder="123456" value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))} error={fields.code} />
          <PrimaryButton type="submit" busy={busy} staff={staff}>Verify code</PrimaryButton>
          <SecondaryButton type="button" onClick={back}>Back to Login</SecondaryButton>
        </form>
      )}

      {step === "approval" && (
        <div className="space-y-4">
          <p className="text-sm text-slate-600 leading-relaxed">
            Your code was confirmed. Your request to reset the password for <b className="break-all">{flow.email}</b> was sent to an
            administrator for approval.
          </p>
          <p className="text-sm text-slate-600 leading-relaxed">
            Once it is approved, an email with a temporary password is sent to this address. Sign in with it on the Staff login screen
            and you will be asked to choose your own password straight away.
          </p>
          <PrimaryButton type="button" staff={staff} onClick={back}>Back to Login</PrimaryButton>
        </div>
      )}

      {step === "password" && (
        <form onSubmit={setNewPassword} className="space-y-4" noValidate>
          <PasswordField label="New password" name="password" autoComplete="new-password" placeholder="At least 10 characters"
                         value={password} onChange={(e) => setPassword(e.target.value)} error={fields.password} />
          <PasswordField label="Confirm password" name="confirm" autoComplete="new-password" placeholder="Repeat your password"
                         value={confirm} onChange={(e) => setConfirm(e.target.value)} error={fields.confirm} />
          <PrimaryButton type="submit" busy={busy} staff={staff}>Update Password</PrimaryButton>
          <SecondaryButton type="button" onClick={back}>Back to Login</SecondaryButton>
        </form>
      )}
    </AuthShell>
  );
}
