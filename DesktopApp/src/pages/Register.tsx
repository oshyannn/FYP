import { useState } from "react";
import type { ChangeEvent, FormEvent } from "react";
import AuthShell from "../components/AuthShell";
import { Field, PasswordField } from "../components/Field";
import { Alert, PrimaryButton, SecondaryButton } from "../components/ui";
import { api, problem } from "../api";
import type { Flow, Screen } from "../types";

interface Props {
  go: (screen: Screen, flow?: Flow) => void;
}

// There is no "account type" here on purpose: the server only ever creates normal user accounts.
export default function Register({ go }: Props) {
  const [form, setForm] = useState({ full_name: "", email: "", password: "", confirm: "" });
  const [fields, setFields] = useState<Record<string, string>>({});
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const set = (k: keyof typeof form) => (e: ChangeEvent<HTMLInputElement>) =>
    setForm({ ...form, [k]: e.target.value });

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (busy) return;
    setError("");
    if (form.password !== form.confirm) {
      setFields({ confirm: "Passwords do not match." });
      return;
    }
    setFields({});
    setBusy(true);
    const res = await api.post("/api/auth/register", {
      full_name: form.full_name,
      email: form.email,
      password: form.password,
    });
    setBusy(false);
    if (res.status === 202) {
      go("verify", { email: form.email, portal: "user" });
      return;
    }
    const p = problem(res);
    setFields(p.fields);
    if (!Object.keys(p.fields).length) setError(p.message);
  }

  return (
    <AuthShell portal="user" title="Create Account" subtitle="Join SafeBrowse today">
      {error && <Alert kind="error">{error}</Alert>}
      <form onSubmit={submit} className="space-y-4" noValidate>
        <Field label="Full Name" name="full_name" autoComplete="name" placeholder="John Tan"
               value={form.full_name} onChange={set("full_name")} error={fields.full_name} />
        <Field label="Email" name="email" type="email" autoComplete="email" placeholder="you@example.com"
               value={form.email} onChange={set("email")} error={fields.email} />
        <PasswordField label="Password" name="password" autoComplete="new-password" placeholder="At least 10 characters"
                       value={form.password} onChange={set("password")} error={fields.password} />
        <PasswordField label="Confirm Password" name="confirm" autoComplete="new-password" placeholder="Repeat your password"
                       value={form.confirm} onChange={set("confirm")} error={fields.confirm} />
        <p className="text-xs text-slate-500">
          Use at least 10 characters with a letter and a number. We email you a link and a 6-digit code to confirm your address.
        </p>
        <PrimaryButton type="submit" busy={busy}>Register</PrimaryButton>
        <SecondaryButton type="button" onClick={() => go("user-login")}>Back to Login</SecondaryButton>
      </form>
    </AuthShell>
  );
}
