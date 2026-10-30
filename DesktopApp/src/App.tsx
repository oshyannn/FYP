import { useEffect, useState } from "react";
import ForgotPassword from "./pages/auth/ForgotPassword";
import StaffApp from "./pages/staff/StaffApp";
import UserApp from "./pages/user/UserApp";
import Register from "./pages/auth/Register";
import ResetPassword from "./pages/auth/ResetPassword";
import StaffLogin from "./pages/auth/StaffLogin";
import StaffRequestAccess from "./pages/auth/StaffRequestAccess";
import UserLogin from "./pages/auth/UserLogin";
import VerifyEmail from "./pages/auth/VerifyEmail";
import type { Flow, Screen, Session } from "./types";

export default function App() {
  const [session, setSession] = useState<Session | null>(null);
  const [booting, setBooting] = useState(true);
  const [screen, setScreen] = useState<Screen>("user-login");
  const [flow, setFlow] = useState<Flow | null>(null);

  // Reopen the app: sign back in if "Remember me" was used and the server still accepts the saved session.
  useEffect(() => {
    window.sb
      .restoreSession()
      .then((s) => {
        if (s) {
          setSession(s);
          setScreen("home");
        }
      })
      .finally(() => setBooting(false));
  }, []);

  const go = (next: Screen, f?: Flow) => {
    setScreen(next);
    setFlow(f ?? null);
  };
  const loggedIn = (s: Session) => {
    setSession(s);
    setFlow(null);
    setScreen("home");
  };
  const loggedOut = () => {
    const wasStaff = session?.portal === "staff";
    setSession(null);
    go(wasStaff ? "staff-login" : "user-login");
  };

  if (booting) {
    return <div className="h-full flex items-center justify-center text-sm text-slate-500">Loading…</div>;
  }
  if (session && screen === "home") {
    return session.portal === "staff" ? (
      <StaffApp session={session} onLogout={loggedOut} />
    ) : (
      <UserApp session={session} onLogout={loggedOut} />
    );
  }

  const verifyFlow: Flow = flow ?? { email: "", portal: "user" };
  switch (screen) {
    case "register":
      return <Register go={go} />;
    case "verify":
      return <VerifyEmail flow={verifyFlow} go={go} onLoggedIn={loggedIn} />;
    case "forgot":
      return <ForgotPassword portal="user" go={go} />;
    case "reset":
      return <ResetPassword flow={verifyFlow} go={go} />;
    case "staff-login":
      return <StaffLogin go={go} onLoggedIn={loggedIn} notice={flow?.notice} />;
    case "staff-request":
      return <StaffRequestAccess go={go} />;
    case "staff-forgot":
      return <ForgotPassword portal="staff" go={go} />;
    case "staff-reset":
      return <ResetPassword flow={{ ...verifyFlow, portal: "staff" }} go={go} />;
    default:
      return <UserLogin go={go} onLoggedIn={loggedIn} notice={flow?.notice} />;
  }
}
