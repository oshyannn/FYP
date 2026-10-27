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

// Employer application. Administrator accounts cannot be requested here (there is no such option anywhere).
export default function StaffRequestAccess({ go }: Props) {
  const [form, setForm] = useState({
    full_name: "", email: "", company_name: "", company_registration_no: "", password: "", confirm: "",
  });
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
    const res = await api.post("/api/staff/request-access", {
      full_name: form.full_name,
      email: form.email,
      company_name: form.company_name,
      company_registration_no: form.company_registration_no,
      password: form.password,
    });
    setBusy(false);
    if (res.status === 202) {
      go("verify", { email: form.email, portal: "staff" });
      return;
    }
    const p = problem(res);
    setFields(p.fields);
    if (!Object.keys(p.fields).length) setError(p.message);
  }

  return (
    <AuthShell portal="staff" title="Request Employer Access" subtitle="An administrator reviews every request">
      {error && <Alert kind="error">{error}</Alert>}
      <form onSubmit={submit} className="space-y-4" noValidate>
        <Field label="Full Name" name="full_name" autoComplete="name" placeholder="John Tan"
               value={form.full_name} onChange={set("full_name")} error={fields.full_name} />
        <Field label="Work email" name="email" type="email" autoComplete="email" placeholder="name@company.com"
               value={form.email} onChange={set("email")} error={fields.email} />
        <Field label="Company name" name="company_name" autoComplete="organization" placeholder="Your company"
               value={form.company_name} onChange={set("company_name")} error={fields.company_name} />
        <Field label="Company registration no." name="company_registration_no" autoComplete="off" placeholder="e.g. 202401012345"
               value={form.company_registration_no} onChange={set("company_registration_no")} error={fields.company_registration_no} />
        <PasswordField label="Password" name="password" autoComplete="new-password" placeholder="At least 10 characters"
                       value={form.password} onChange={set("password")} error={fields.password} />
        <PasswordField label="Confirm Password" name="confirm" autoComplete="new-password" placeholder="Repeat your password"
                       value={form.confirm} onChange={set("confirm")} error={fields.confirm} />
        <p className="text-xs text-slate-500">
          Administrator accounts cannot be requested here. Approved employers sign in on the staff login page.
        </p>
        <PrimaryButton type="submit" busy={busy} staff>Submit Request</PrimaryButton>
        <SecondaryButton type="button" onClick={() => go("staff-login")}>Back to Staff Login</SecondaryButton>
      </form>
    </AuthShell>
  );
}
