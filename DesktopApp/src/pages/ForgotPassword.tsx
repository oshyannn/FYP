import { useState } from "react";
import type { FormEvent } from "react";
import AuthShell from "../components/AuthShell";
import { Field } from "../components/Field";
import { Alert, PrimaryButton, SecondaryButton } from "../components/ui";
import { api, problem } from "../api";
import type { Flow, Screen } from "../types";

interface Props {
  portal: "user" | "staff";
  go: (screen: Screen, flow?: Flow) => void;
}

export default function ForgotPassword({ portal, go }: Props) {
  const [email, setEmail] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const staff = portal === "staff";

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (busy) return;
    setBusy(true);
    setError("");
    const res = await api.post(staff ? "/api/staff/forgot-password" : "/api/auth/forgot-password", { email });
    setBusy(false);
    if (res.status === 202) {
      go(staff ? "staff-reset" : "reset", { email, portal });
      return;
    }
    setError(problem(res).message);
  }

  return (
    <AuthShell portal={portal} title="Reset Password" subtitle="We'll send a 6-digit code to your email.">
      {error && <Alert kind="error">{error}</Alert>}
      <form onSubmit={submit} className="space-y-4" noValidate>
        <Field label="Email Address" name="email" type="email" autoComplete="username" placeholder="you@example.com"
               value={email} onChange={(e) => setEmail(e.target.value)} />
        <PrimaryButton type="submit" busy={busy} staff={staff}>Send Recovery Email</PrimaryButton>
        <SecondaryButton type="button" onClick={() => go(staff ? "staff-login" : "user-login")}>Back to Login</SecondaryButton>
      </form>
    </AuthShell>
  );
}
