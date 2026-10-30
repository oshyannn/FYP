import { useEffect, useState } from "react";
import type { FormEvent } from "react";
import AuthShell from "../../components/AuthShell";
import { Field } from "../../components/Field";
import { Alert, LinkButton, PrimaryButton } from "../../components/ui";
import { api, problem } from "../../api";
import type { Flow, Screen, Session } from "../../types";

interface Props {
  flow: Flow;
  go: (screen: Screen, flow?: Flow) => void;
  onLoggedIn: (session: Session) => void;
}

const RESEND_SECONDS = 60;

export default function VerifyEmail({ flow, go, onLoggedIn }: Props) {
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [info, setInfo] = useState(flow.notice ?? "");
  const [cooldown, setCooldown] = useState(0);
  const [handoffGone, setHandoffGone] = useState(false);
  const staff = flow.portal === "staff";

  // User sign-up: while this screen is open, the app waits for the email link to be confirmed (on any device) and
  // then signs in automatically. Only this app can complete it, because only it holds the secret.
  useEffect(() => {
    if (staff) return;
    let active = true;
    const id = window.setInterval(async () => {
      const res = await api.post("/api/auth/complete-signup", { email: flow.email });
      if (!active) return;
      if (res.status === 200 && res.data?.user) {
        active = false;
        window.clearInterval(id);
        onLoggedIn({ user: res.data.user, portal: res.data.portal });
      } else if (res.status !== 202 && res.status !== 0) {
        active = false;
        window.clearInterval(id);
        setHandoffGone(true);
      }
    }, 3000);
    return () => {
      active = false;
      window.clearInterval(id);
    };
  }, [flow.email, staff]);

  useEffect(() => {
    if (cooldown <= 0) return;
    const id = window.setTimeout(() => setCooldown(cooldown - 1), 1000);
    return () => window.clearTimeout(id);
  }, [cooldown]);

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (busy) return;
    if (!/^\d{6}$/.test(code)) {
      setError("Enter the 6-digit code from the email.");
      return;
    }
    setBusy(true);
    setError("");
    const res = await api.post("/api/auth/verify-email", { email: flow.email, code });
    setBusy(false);
    if (res.status === 200 && res.data?.user) {
      onLoggedIn({ user: res.data.user, portal: res.data.portal });
      return;
    }
    if (res.status === 200) {
      go(staff ? "staff-login" : "user-login", {
        email: flow.email,
        portal: flow.portal,
        notice: staff
          ? "Email verified. An administrator will review your request; you can log in once it is approved."
          : "Email verified. Log in to continue.",
      });
      return;
    }
    setError(problem(res).message);
  }

  async function resend() {
    setError("");
    const res = await api.post("/api/auth/resend-code", { email: flow.email });
    if (res.status === 202) {
      setInfo("If your account is waiting for verification, we sent a new email.");
      setCooldown(RESEND_SECONDS);
    } else {
      setError(problem(res).message);
    }
  }

  return (
    <AuthShell
      portal={flow.portal}
      title="Check your email"
      subtitle={flow.email}
      footer={
        <LinkButton onClick={() => go(staff ? "staff-login" : "user-login")}>← Back to login</LinkButton>
      }
    >
      {info && <Alert kind="info">{info}</Alert>}
      {error && <Alert kind="error">{error}</Alert>}
      {handoffGone && (
        <Alert kind="info">
          Automatic sign-in is no longer available for this sign-up. If you already verified, go back and log in with your password.
        </Alert>
      )}
      <p className="text-sm text-slate-600 mb-1 font-medium">Option 1 — click the link in the email</p>
      <p className="text-xs text-slate-500 mb-5">
        {staff
          ? "Open the link and press the confirm button."
          : "Open the link and press the confirm button. This app signs you in automatically."}
      </p>
      <p className="text-sm text-slate-600 mb-3 font-medium">Option 2 — enter the 6-digit code</p>
      <form onSubmit={submit} className="space-y-4" noValidate>
        <Field label="Verification code" name="code" inputMode="numeric" autoComplete="one-time-code" maxLength={6}
               placeholder="123456" value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))} />
        <PrimaryButton type="submit" busy={busy} staff={staff}>Verify</PrimaryButton>
      </form>
      <p className="text-center text-sm text-slate-500 mt-5">
        Didn't get it?{" "}
        {cooldown > 0 ? (
          <span>Resend in {cooldown}s</span>
        ) : (
          <LinkButton onClick={resend}>Resend email</LinkButton>
        )}
      </p>
    </AuthShell>
  );
}
