import { useEffect, useRef, useState } from "react";
import ForgotPassword from "./pages/auth/ForgotPassword";
import StaffApp from "./pages/staff/StaffApp";
import UserApp from "./pages/user/UserApp";
import Register from "./pages/auth/Register";
import ResetPassword from "./pages/auth/ResetPassword";
import StaffLogin from "./pages/auth/StaffLogin";
import StaffRequestAccess from "./pages/auth/StaffRequestAccess";
import UserLogin from "./pages/auth/UserLogin";
import VerifyEmail from "./pages/auth/VerifyEmail";
import type { Flow, OpenRequest, Screen, Session } from "./types";

/** First 16 hex chars of SHA-256(lower-case email): the same value the extension puts in its link. */
async function accountTag(email: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(email.trim().toLowerCase()));
  return Array.from(new Uint8Array(buf)).slice(0, 8).map((b) => b.toString(16).padStart(2, "0")).join("");
}

export interface AppRoute {
  page: "dashboard" | "history" | "scanner";
  scan: string | null; // open the detailed analysis of this saved scan
  n: number; // changes with every request so the same page can be opened again
}

export default function App() {
  const [session, setSession] = useState<Session | null>(null);
  const [booting, setBooting] = useState(true);
  const [screen, setScreen] = useState<Screen>("user-login");
  const [flow, setFlow] = useState<Flow | null>(null);
  const [route, setRoute] = useState<AppRoute | null>(null); // a page the browser extension asked for
  const [ask, setAsk] = useState<OpenRequest | null>(null); // the extension's account differs: waiting for the person's answer
  const [asking, setAsking] = useState(false);
  const [linkMsg, setLinkMsg] = useState("");
  const sessionRef = useRef<Session | null>(null);
  sessionRef.current = session;

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

  // The browser extension opened the app (safebrowse://history ...). The link names the extension's account; the page is
  // opened only for that same account. If another account (or nobody) is signed in here, the person is asked first.
  useEffect(() => {
    if (booting) return;
    const take = async () => {
      const req = await window.sb.takePendingPage();
      if (!req) return;
      const cur = sessionRef.current;
      if (cur && cur.portal === "user" && req.acct && (await accountTag(cur.user.email)) === req.acct) {
        window.sb.dropLink();
        setLinkMsg("");
        setRoute({ page: req.page, scan: req.scan, n: Date.now() });
      } else if (req.hasCode) {
        setLinkMsg("");
        setAsk(req);
      } else if (cur) {
        setLinkMsg("The browser extension is connected to a different account than the one signed in here, so nothing was opened. Log out and sign in with the extension's account.");
      }
    };
    take();
    return window.sb.onOpenPage(take);
  }, [booting]);

  async function switchAccount() {
    if (!ask) return;
    setAsking(true);
    const s = await window.sb.acceptLink();
    setAsking(false);
    if (s) {
      setSession(s);
      setFlow(null);
      setScreen("home");
      setLinkMsg("");
      setRoute({ page: ask.page, scan: ask.scan, n: Date.now() });
    } else {
      setLinkMsg("That link has expired. Press the button in the extension again.");
    }
    setAsk(null);
  }
  function cancelSwitch() {
    window.sb.dropLink();
    setAsk(null);
  }

  const go = (next: Screen, f?: Flow) => {
    setScreen(next);
    setFlow(f ?? null);
  };
  const loggedIn = (s: Session) => {
    setSession(s);
    setFlow(null);
    setRoute(null);
    setScreen("home");
  };
  const loggedOut = () => {
    const wasStaff = session?.portal === "staff";
    setSession(null);
    setRoute(null);
    go(wasStaff ? "staff-login" : "user-login");
  };

  const screens = (() => {
    if (booting) {
      return <div className="h-full flex items-center justify-center text-sm text-slate-500">Loading…</div>;
    }
    if (session && screen === "home") {
      return session.portal === "staff" ? (
        <StaffApp key={session.user.id} session={session} onLogout={loggedOut} />
      ) : (
        <UserApp key={session.user.id} session={session} onLogout={loggedOut} route={route} />
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
  })();

  const cur = session?.user.email;
  return (
    <>
      {screens}
      {linkMsg && !ask && (
        <div className="fixed bottom-4 left-1/2 -translate-x-1/2 max-w-md bg-amber-50 border border-amber-300 text-amber-900 text-sm rounded-xl shadow-lg px-4 py-3 flex gap-3 items-start">
          <span>{linkMsg}</span>
          <button onClick={() => setLinkMsg("")} className="text-amber-700 font-semibold">OK</button>
        </div>
      )}
      {ask && (
        <div className="fixed inset-0 bg-black/40 flex items-center justify-center p-4 z-50">
          <div role="dialog" aria-modal="true" className="bg-white rounded-2xl shadow-xl max-w-md w-full p-6">
            <h2 className="text-base font-semibold text-slate-900">Different account</h2>
            <p className="text-sm text-slate-600 mt-2 leading-relaxed">
              Your browser extension is connected to <b>{ask.hint ?? "another account"}</b>
              {cur ? ", but this app is signed in with a different account." : ", and you are not signed in here."} Switch to
              the extension's account and open {ask.scan ? "the detailed analysis" : ask.page === "history" ? "your detection history" : "the app"}?
            </p>
            <div className="flex gap-3 mt-5">
              <button disabled={asking} onClick={switchAccount} className="flex-1 bg-[#1e3a5f] text-white rounded-lg py-2 text-sm font-semibold disabled:opacity-60">
                {asking ? "Switching…" : "Yes, switch"}
              </button>
              <button disabled={asking} onClick={cancelSwitch} className="flex-1 border border-slate-300 text-slate-700 rounded-lg py-2 text-sm font-semibold">
                No, cancel
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
