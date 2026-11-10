import { useEffect, useState } from "react";
import type { FormEvent } from "react";
import AuthShell from "../../components/AuthShell";
import { Field, PasswordField } from "../../components/Field";
import { Alert, LinkButton, PrimaryButton, SecondaryButton } from "../../components/ui";
import { api, problem } from "../../api";
import type { Flow, Screen } from "../../types";

interface Props {
  portal: "user" | "staff";
  go: (screen: Screen, flow?: Flow) => void;
}

// Steps: choose -> (code, if self) -> enter code -> new password.
// "self": a 6-digit code is emailed now (users only).
// "help": an approver must approve first; then the code is emailed to the account (users, employers and admins).
type Step = "email" | "waiting" | "code" | "password";
const RESEND_SECONDS = 60;

export default function ForgotPassword({ portal, go }: Props) {
  const staff = portal === "staff";
  const [step, setStep] = useState<Step>("email");
  const [method, setMethod] = useState<"self" | "help">(staff ? "help" : "self");
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

  // Step 1: email, and the chosen way.
  async function sendFirst(e: FormEvent) {
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
    if (method === "self") {
      const res = await api.post("/api/auth/forgot-password", { email: email.trim() });
      setBusy(false);
      if (res.status !== 202) return setError(problem(res).message);
      setCooldown(RESEND_SECONDS);
      setInfo("If this address has an account, a 6-digit code was sent to it.");
      setStep("code");
      return;
    }
    const res = await api.post("/api/auth/reset-request", { email: email.trim() });
    setBusy(false);
    if (res.status !== 202) return setError(problem(res).message);
    setStep("waiting");
  }

  // Self only: send a new code (the older one stops working). Cooldown stops repeated clicks.
  async function resend() {
    if (busy || cooldown > 0) return;
    setBusy(true);
    setError("");
    const res = await api.post("/api/auth/forgot-password", { email: email.trim() });
    setBusy(false);
    if (res.status !== 202) return setError(problem(res).message);
    setCode("");
    setCooldown(RESEND_SECONDS);
    setInfo("A new code was sent. The previous code no longer works.");
  }

  // Step 2: check the code. Only when it is right do we move on to the password.
  async function checkCode(e: FormEvent) {
    e.preventDefault();
    if (busy) return;
    if (!/^\d{6}$/.test(code)) {
      setFields({ code: "Enter the 6-digit code from the email." });
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
    step === "email" ? "Choose how to reset your password" : step === "waiting" ? "Waiting for approval" : step === "code" ? `Code sent to ${email.trim()}` : "Choose a new password";

  return (
    <AuthShell portal={portal} title="Reset Password" subtitle={subtitle}>
      {error && <Alert kind="error">{error}</Alert>}
      {info && <Alert kind="success">{info}</Alert>}

      {step === "email" && (
        <form onSubmit={sendFirst} className="space-y-4" noValidate>
          {!staff && (
            <div className="grid grid-cols-2 gap-2" role="radiogroup" aria-label="How do you want to reset?">
              {([
                ["self", "Verify myself", "We email a code to you"],
                ["help", "Ask for help", "An administrator or employer approves first"],
              ] as const).map(([k, t, d]) => (
                <button
                  key={k}
                  type="button"
                  role="radio"
                  aria-checked={method === k}
                  onClick={() => setMethod(k)}
                  className={`text-left border rounded-xl p-3 text-sm ${method === k ? "border-[#1e3a5f] ring-2 ring-[#1e3a5f]/15" : "border-slate-300"}`}
                >
                  <span className="block font-semibold text-slate-800">{t}</span>
                  <span className="block text-xs text-slate-500 mt-1">{d}</span>
                </button>
              ))}
            </div>
          )}
          {staff && (
            <p className="text-sm text-slate-500">
              Staff accounts are reset with an approval. Enter your work email and an approver will be asked.
            </p>
          )}
          <Field label="Email" name="email" type="email" autoComplete="username" placeholder="you@example.com"
                 value={email} onChange={(e) => setEmail(e.target.value)} error={fields.email} />
          <PrimaryButton type="submit" busy={busy} staff={staff}>
            {method === "self" && !staff ? "Send code" : "Send request"}
          </PrimaryButton>
          <SecondaryButton type="button" onClick={back}>Back to Login</SecondaryButton>
        </form>
      )}

      {step === "waiting" && (
        <div className="space-y-4">
          <p className="text-sm text-slate-600 leading-relaxed">
            Your request was sent. An approver will review it. Once approved, a 6-digit code is emailed to your address.
            Come back here when you have the code.
          </p>
          <PrimaryButton type="button" staff={staff} onClick={() => setStep("code")}>I have the code</PrimaryButton>
          <SecondaryButton type="button" onClick={back}>Back to Login</SecondaryButton>
        </div>
      )}

      {step === "code" && (
        <form onSubmit={checkCode} className="space-y-4" noValidate>
          <Field label="6-digit code" name="code" inputMode="numeric" autoComplete="one-time-code" maxLength={6}
                 placeholder="123456" value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))} error={fields.code} />
          <div className="flex items-center justify-between text-sm">
            {method === "self" ? (
              <button type="button" onClick={resend} disabled={busy || cooldown > 0} className="text-[#1e3a5f] font-medium disabled:text-slate-400">
                {cooldown > 0 ? `Resend code in ${cooldown}s` : "Resend code"}
              </button>
            ) : (
              <span className="text-slate-500">No code yet? Check the approval status with your administrator.</span>
            )}
          </div>
          <PrimaryButton type="submit" busy={busy} staff={staff}>Verify code</PrimaryButton>
          <SecondaryButton type="button" onClick={back}>Back to Login</SecondaryButton>
        </form>
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

      {step !== "email" && step !== "password" && (
        <p className="text-center text-sm text-slate-500 mt-5">
          <LinkButton onClick={() => setStep("email")}>Use a different email</LinkButton>
        </p>
      )}
    </AuthShell>
  );
}
