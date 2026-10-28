import { useEffect, useState } from "react";
import { api, problem } from "../api";
import { Alert, SecondaryButton } from "../components/ui";
import type { Session } from "../types";
import type { ReactNode } from "react";
import type { ScanRecord } from "../lib/analysis";
import StaffFeedback from "./StaffFeedback";
import Feedback from "./user/feedback/Feedback";
import ScanApp from "./user/ScanApp";

interface Device {
  id: string;
  label: string | null;
  paired_at: string;
  last_seen_at: string;
}

interface Props {
  session: Session;
  onLogout: () => void;
}

// Signed-in home. Normal users reach the URL scanner and detection history from here; the extension is paired here too.
export default function Home({ session, onLogout }: Props) {
  const { user, portal } = session;
  const staff = portal === "staff";
  const [error, setError] = useState("");
  const [pair, setPair] = useState<{ code: string; expiresAt: number } | null>(null);
  const [left, setLeft] = useState(0);
  const [devices, setDevices] = useState<Device[]>([]);
  const [view, setView] = useState<"home" | "scan" | "feedback" | "staff-feedback">("home");
  const [reportScan, setReportScan] = useState<ScanRecord | null>(null); // a scan the user is reporting as wrongly detected

  // Any 401 means the session ended (expired, revoked, password changed): go back to the login screen.
  function expired(status: number) {
    if (status === 401) {
      onLogout();
      return true;
    }
    return false;
  }

  async function loadDevices() {
    const res = await api.get("/api/extension/devices");
    if (expired(res.status)) return;
    if (res.status === 200) setDevices(res.data.devices);
  }

  useEffect(() => {
    if (!staff) loadDevices();
  }, []);

  useEffect(() => {
    if (!pair) return;
    const tick = () => {
      const s = Math.max(0, Math.round((pair.expiresAt - Date.now()) / 1000));
      setLeft(s);
      if (s === 0) setPair(null);
    };
    tick();
    const id = window.setInterval(tick, 1000);
    return () => window.clearInterval(id);
  }, [pair]);

  async function generate() {
    setError("");
    const res = await api.post("/api/extension/pairing-code");
    if (expired(res.status)) return;
    if (res.status === 200) setPair({ code: res.data.code, expiresAt: Date.now() + res.data.expires_in * 1000 });
    else setError(problem(res).message);
  }

  async function disconnect(id: string) {
    const res = await api.del(`/api/extension/devices/${id}`);
    if (expired(res.status)) return;
    loadDevices();
  }

  async function logout() {
    await api.post("/api/auth/logout");
    onLogout();
  }

  // A full-page screen opened from the home cards, with a "Back to home" button.
  const subpage = (body: ReactNode) => (
    <div className="h-full overflow-y-auto bg-slate-50">
      <header className={`${staff ? "bg-[#14284a]" : "bg-[#1e3a5f]"} text-white`}>
        <div className="max-w-6xl mx-auto px-6 py-4 flex items-center justify-between">
          <h1 className="text-lg font-bold">SafeBrowse{staff ? " Staff" : ""}</h1>
          <button
            onClick={() => {
              setReportScan(null);
              setView("home");
            }}
            className="text-sm border border-white/30 rounded-lg px-3 py-1.5 hover:bg-white/10"
          >
            Back to home
          </button>
        </div>
      </header>
      <main className="max-w-6xl mx-auto px-6 py-8">{body}</main>
    </div>
  );

  if (view === "scan") {
    return (
      <ScanApp
        onBack={() => setView("home")}
        onLogout={onLogout}
        onReport={(s) => {
          setReportScan(s);
          setView("feedback");
        }}
      />
    );
  }

  if (view === "feedback" && !staff) {
    return subpage(<Feedback key={reportScan?.id ?? "none"} initialScan={reportScan} onSessionEnd={onLogout} />);
  }

  if (view === "staff-feedback" && staff) {
    return subpage(<StaffFeedback onSessionEnd={onLogout} />);
  }

  return (
    <div className="h-full overflow-y-auto bg-slate-50">
      <header className={`${staff ? "bg-[#14284a]" : "bg-[#1e3a5f]"} text-white`}>
        <div className="max-w-3xl mx-auto px-6 py-4 flex items-center justify-between">
          <div>
            <h1 className="text-lg font-bold">SafeBrowse{staff ? " Staff" : ""}</h1>
            <p className="text-xs text-white/70">
              {user.full_name ?? user.email} · {user.role}
            </p>
          </div>
          <button onClick={logout} className="text-sm border border-white/30 rounded-lg px-3 py-1.5 hover:bg-white/10">
            Log out
          </button>
        </div>
      </header>

      <main className="max-w-3xl mx-auto px-6 py-8 space-y-6">
        <section className="bg-white border border-slate-200 rounded-2xl p-6">
          <h2 className="text-base font-semibold text-slate-900">You are signed in</h2>
          <p className="text-sm text-slate-500 mt-1">
            Authentication works. The {staff ? "staff" : "user"} screens will be built on top of this one.
          </p>
        </section>

        {!staff && (
          <section className="bg-white border border-slate-200 rounded-2xl p-6">
            <h2 className="text-base font-semibold text-slate-900">URL Scanner</h2>
            <p className="text-sm text-slate-500 mt-1 mb-4">
              Check a website address before you visit it, and review your detection history.
            </p>
            <div className="max-w-xs">
              <SecondaryButton onClick={() => setView("scan")}>Open URL Scanner</SecondaryButton>
            </div>
          </section>
        )}

        <section className="bg-white border border-slate-200 rounded-2xl p-6">
          <h2 className="text-base font-semibold text-slate-900">{staff ? "User Feedback" : "Feedback"}</h2>
          <p className="text-sm text-slate-500 mt-1 mb-4">
            {staff
              ? "Review feedback and wrong-detection reports from users, reply to them and close them."
              : "Report a wrong detection or suggest an improvement, and follow the replies to your feedback."}
          </p>
          <div className="max-w-xs">
            <SecondaryButton
              onClick={() => {
                setReportScan(null);
                setView(staff ? "staff-feedback" : "feedback");
              }}
            >
              {staff ? "Open User Feedback" : "Open Feedback"}
            </SecondaryButton>
          </div>
        </section>

        {!staff && (
          <section className="bg-white border border-slate-200 rounded-2xl p-6">
            <h2 className="text-base font-semibold text-slate-900">Browser extension</h2>
            <p className="text-sm text-slate-500 mt-1 mb-4">
              Generate a pairing code and type it into the SafeBrowse extension. The extension never needs your password.
            </p>
            {error && <Alert kind="error">{error}</Alert>}
            {pair ? (
              <div className="rounded-xl bg-slate-50 border border-slate-200 p-4 text-center">
                <p className="text-3xl font-bold tracking-widest text-[#1e3a5f]">{pair.code}</p>
                <p className="text-xs text-slate-500 mt-1">
                  One-time code, valid for {Math.floor(left / 60)}:{String(left % 60).padStart(2, "0")}
                </p>
              </div>
            ) : (
              <div className="max-w-xs">
                <SecondaryButton onClick={generate}>Generate pairing code</SecondaryButton>
              </div>
            )}

            <h3 className="text-sm font-semibold text-slate-900 mt-6 mb-2">Connected extensions</h3>
            {devices.length === 0 ? (
              <p className="text-sm text-slate-500">None yet.</p>
            ) : (
              <ul className="divide-y divide-slate-100">
                {devices.map((d) => (
                  <li key={d.id} className="py-2 flex items-center justify-between text-sm">
                    <span className="text-slate-700">
                      {d.label ?? "Browser extension"}
                      <span className="text-slate-400"> · paired {new Date(d.paired_at).toLocaleDateString()}</span>
                    </span>
                    <button onClick={() => disconnect(d.id)} className="text-red-600 hover:underline text-xs">
                      Disconnect
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </section>
        )}
      </main>
    </div>
  );
}
