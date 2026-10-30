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

export default function UserLogin({ go, onLoggedIn, notice }: Props) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [remember, setRemember] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (busy) return;
    setBusy(true);
    setError("");
    const res = await api.post("/api/auth/login", { email, password, remember });
    setBusy(false);
    if (res.status === 200) {
      onLoggedIn({ user: res.data.user, portal: res.data.portal });
      return;
    }
    if (res.status === 403 && res.data?.error?.code === "email_not_verified") {
      go("verify", { email, portal: "user", notice: res.data.error.message });
      return;
    }
    setError(problem(res).message);
  }

  return (
    <AuthShell
      portal="user"
      title="SafeBrowse"
      subtitle="Welcome back"
      footer={
        <>
          Employer or administrator? <LinkButton onClick={() => go("staff-login")}>Staff login</LinkButton>
        </>
      }
    >
      {notice && <Alert kind="success">{notice}</Alert>}
      {error && <Alert kind="error">{error}</Alert>}
      <form onSubmit={submit} className="space-y-4" noValidate>
        <Field label="Email" name="email" type="email" autoComplete="username" placeholder="you@example.com"
               value={email} onChange={(e) => setEmail(e.target.value)} />
        <PasswordField label="Password" name="password" autoComplete="current-password" placeholder="••••••••"
                       value={password} onChange={(e) => setPassword(e.target.value)} />
        <div className="flex items-center justify-between">
          <label className="flex items-center gap-2 cursor-pointer">
            <input type="checkbox" checked={remember} onChange={(e) => setRemember(e.target.checked)}
                   className="w-4 h-4 accent-[#1e3a5f]" />
            <span className="text-sm text-slate-600">Remember me</span>
          </label>
          <LinkButton onClick={() => go("forgot")} className="text-sm">Forgot Password?</LinkButton>
        </div>
        <PrimaryButton type="submit" busy={busy}>Login</PrimaryButton>
      </form>
      <p className="text-center text-sm text-slate-500 mt-5">
        Don't have an account? <LinkButton onClick={() => go("register")}>Create Account</LinkButton>
      </p>
    </AuthShell>
  );
}
