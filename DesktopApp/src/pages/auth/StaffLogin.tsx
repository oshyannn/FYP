import { useState } from "react";
import type { FormEvent } from "react";
import AuthShell from "../../components/AuthShell";
import { Field, PasswordField } from "../../components/Field";
import { Alert, LinkButton, PrimaryButton } from "../../components/ui";
import { api, problem } from "../../api";
import type { Flow, Screen, Session } from "../../types";

interface Props {
  go: (screen: Screen, flow?: Flow) => void;
  onLoggedIn: (session: Session) => void;
  notice?: string;
}

export default function StaffLogin({ go, onLoggedIn, notice }: Props) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (busy) return;
    setBusy(true);
    setError("");
    const res = await api.post("/api/staff/login", { email, password });
    setBusy(false);
    if (res.status === 200) {
      onLoggedIn({ user: res.data.user, portal: res.data.portal });
      return;
    }
    if (res.status === 403 && res.data?.error?.code === "email_not_verified") {
      go("verify", { email, portal: "staff", notice: res.data.error.message });
      return;
    }
    setError(problem(res).message);
  }

  return (
    <AuthShell
      portal="staff"
      title="SafeBrowse Staff"
      subtitle="Employer and administrator sign-in"
      footer={<LinkButton onClick={() => go("user-login")}>← Back to user login</LinkButton>}
    >
      {notice && <Alert kind="success">{notice}</Alert>}
      {error && <Alert kind="error">{error}</Alert>}
      <form onSubmit={submit} className="space-y-4" noValidate>
        <Field label="Work email" name="email" type="email" autoComplete="username" placeholder="name@company.com"
               value={email} onChange={(e) => setEmail(e.target.value)} />
        <PasswordField label="Password" name="password" autoComplete="current-password" placeholder="••••••••"
                       value={password} onChange={(e) => setPassword(e.target.value)} />
        <div className="flex justify-end">
          <LinkButton onClick={() => go("staff-forgot")} className="text-sm">Forgot Password?</LinkButton>
        </div>
        <PrimaryButton type="submit" busy={busy} staff>Staff Login</PrimaryButton>
      </form>
      <p className="text-center text-sm text-slate-500 mt-5">
        Employer without an account? <LinkButton onClick={() => go("staff-request")}>Request Access</LinkButton>
      </p>
    </AuthShell>
  );
}
