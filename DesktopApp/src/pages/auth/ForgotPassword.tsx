import { useEffect, useState } from "react";
import type { FormEvent } from "react";
import AuthShell from "../../components/AuthShell";
import { Field, PasswordField } from "../../components/Field";
import { Alert, LinkButton, PrimaryButton, SecondaryButton } from "../../components/ui";
import { api, problem } from "../../api";
import type { Flow, Screen } from "../../types";

interface Props {
  /** only decides the colour and where "Back to Login" goes: the steps are the same for everybody */
  portal: "user" | "staff";
  go: (screen: Screen, flow?: Flow) => void;
}

// Step 1: email. The server answers which way this account resets:
//   "code"     a normal user: a 6-digit PIN was emailed -> step 2 (PIN) -> step 3 (new password)
//   "approval" an employer or administrator: a request now waits for an administrator. When it is approved a temporary
//              password is emailed, and the person must choose their own at the next login.
type Step = "email" | "code" | "approval" | "password";
const RESEND_SECONDS = 60;

export default function ForgotPassword({ portal, go }: Props) {
  const staff = portal === "staff";
  const [step, setStep] = useState<Step>("email");
  const [email, setEmail] = useState("");
  const [code, setCode] = useState("");
  const [ticket, setTicket] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [fields, setFields] = useState<Record<string, string>>({});
  const [error, setError] = useState("");
  const [info, setInfo] = useState("");
  const [busy, setBusy] = useState(false);
  const [cooldown, setCooldown] = useState(0);

  useEffect(() => {
    if (cooldown <= 0) return;
    const t = window.setTimeout(() => setCooldown(cooldown - 1), 1000);
    return () => window.clearTimeout(t);
  }, [cooldown]);

  function back() {
    go(staff ? "staff-login" : "user-login");
  }

  // Step 1: the email.
  async function sendEmail(e: FormEvent) {
    e.preventDefault();
    if (busy) return;
    if (!/^\S+@\S+\.\S+$/.test(email.trim())) {
      setFields({ email: "Enter a valid email address." });
      return;
    }
    setFields({});
    setError("");
    setInfo("");
    setBusy(true);
    const res = await api.post("/api/auth/forgot-password", { email: email.trim() });
    setBusy(false);
    if (res.status !== 202) return setError(problem(res).message);
    if (res.data?.flow === "approval") {
      setStep("approval");
      return;
    }
    setCooldown(RESEND_SECONDS);
    setInfo("If this address has an account, a 6-digit PIN was sent to it.");
    setStep("code");
  }

  // Step 2 (users): send a new PIN (the older one stops working). The cooldown stops repeated clicks.
  async function resend() {
    if (busy || cooldown > 0) return;
    setBusy(true);
    setError("");
    const res = await api.post("/api/auth/forgot-password", { email: email.trim() });
    setBusy(false);
    if (res.status !== 202) return setError(problem(res).message);
    setCode("");
    setCooldown(RESEND_SECONDS);
    setInfo("A new PIN was sent. The previous PIN no longer works.");
  }

  // Step 2: check the PIN. Only when it is right do we move on to the password.
  async function checkCode(e: FormEvent) {
    e.preventDefault();
    if (busy) return;
    if (!/^\d{6}$/.test(code)) {
      setFields({ code: "Enter the 6-digit PIN from the email." });
      return;
    }
    setFields({});
    setError("");
    setInfo("");
    setBusy(true);
    const res = await api.post("/api/auth/reset/verify", { email: email.trim(), code });
    setBusy(false);
    if (res.status === 200) {
      setTicket(res.data.ticket as string);
      setStep("password");
      return;
    }
    setFields({ code: problem(res).message });
  }

  // Step 3: the new password, with the ticket from step 2.
  async function setNewPassword(e: FormEvent) {
    e.preventDefault();
    if (busy) return;
    if (password !== confirm) {
      setFields({ confirm: "Passwords do not match." });
      return;
    }
    setFields({});
    setError("");
    setBusy(true);
    const res = await api.post("/api/auth/reset/set-password", { email: email.trim(), ticket, new_password: password });
    setBusy(false);
    if (res.status === 200) {
      go(staff ? "staff-login" : "user-login", {
        email: email.trim(),
        portal,
        notice: "Password updated. Log in with your new password.",
      });
      return;
    }
    const p = problem(res);
    if (p.fields.new_password) setFields({ password: p.fields.new_password });
    else if (res.status === 400 && p.message.includes("expired")) {
      setError(p.message);
      setStep("email");
    } else setError(p.message);
  }

  const subtitle =
    step === "email"
      ? "Step 1 of 3: enter your email"
      : step === "code"
        ? `Step 2 of 3: enter the PIN sent to ${email.trim()}`
        : step === "approval"
          ? "Request sent"
          : "Step 3 of 3: choose a new password";

  return (
    <AuthShell portal={portal} title="Reset Password" subtitle={subtitle}>
      {error && <Alert kind="error">{error}</Alert>}
      {info && <Alert kind="success">{info}</Alert>}

      {step === "email" && (
        <form onSubmit={sendEmail} className="space-y-4" noValidate>
          <Field label="Email" name="email" type="email" autoComplete="username" placeholder="you@example.com"
                 value={email} onChange={(e) => setEmail(e.target.value)} error={fields.email} />
          <PrimaryButton type="submit" busy={busy} staff={staff}>Continue</PrimaryButton>
          <SecondaryButton type="button" onClick={back}>Back to Login</SecondaryButton>
        </form>
      )}

      {step === "code" && (
        <form onSubmit={checkCode} className="space-y-4" noValidate>
          <Field label="6-digit PIN" name="code" inputMode="numeric" autoComplete="one-time-code" maxLength={6}
                 placeholder="123456" value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))} error={fields.code} />
          <div className="flex items-center justify-between text-sm">
            <button type="button" onClick={resend} disabled={busy || cooldown > 0} className="text-[#1e3a5f] font-medium disabled:text-slate-400">
              {cooldown > 0 ? `Resend PIN in ${cooldown}s` : "Resend PIN"}
            </button>
          </div>
          <PrimaryButton type="submit" busy={busy} staff={staff}>Verify PIN</PrimaryButton>
          <SecondaryButton type="button" onClick={back}>Back to Login</SecondaryButton>
        </form>
      )}

      {step === "approval" && (
        <div className="space-y-4">
          <p className="text-sm text-slate-600 leading-relaxed">
            Your request to reset the password for <b className="break-all">{email.trim()}</b> was sent to an administrator for approval.
          </p>
          <p className="text-sm text-slate-600 leading-relaxed">
            Once it is approved, an email with a temporary password is sent to this address. Sign in with it on the Staff login screen and you
            will be asked to choose your own password straight away.
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

      {step === "code" && (
        <p className="text-center text-sm text-slate-500 mt-5">
          <LinkButton onClick={() => setStep("email")}>Use a different email</LinkButton>
        </p>
      )}
    </AuthShell>
  );
}
