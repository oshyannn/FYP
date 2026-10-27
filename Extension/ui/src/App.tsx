import { useCallback, useEffect, useRef, useState } from "react";
import * as api from "./api";
import * as store from "./store";
import { Footer, Header, NavBar, type Screen } from "./ui";
import {
  ActivityScreen, CheckingScreen, DetailsScreen, HistoryScreen, MaliciousScreen, ManualResultScreen,
  ManualScanScreen, NoticeScreen, PairScreen, SafeScreen, SettingsScreen, SuspiciousScreen,
} from "./screens";
import type { Auth, HistoryRecord, Settings, Verdict } from "./types";

type Boot = "loading" | "pair" | "ready";
type Current =
  | { phase: "idle" }
  | { phase: "checking" }
  | { phase: "done"; verdict: Verdict }
  | { phase: "error"; message: string };

/** The same "allowed until the browser closes" list the warning page uses (blocked.js). */
async function allowHost(url: string) {
  try {
    const host = new URL(url).hostname;
    const s = await chrome.storage.session.get("allowed");
    await chrome.storage.session.set({ allowed: [...new Set([...(s.allowed || []), host])] });
  } catch {}
}

export default function App() {
  const [boot, setBoot] = useState<Boot>("loading");
  const [notice, setNotice] = useState<string | undefined>();
  const [auth, setAuth] = useState<Auth | null>(null);
  const [settings, setSettings] = useState<Settings>(store.DEFAULT_SETTINGS);
  const [history, setHistory] = useState<HistoryRecord[]>([]);
  const [screen, setScreen] = useState<Screen>("status");
  const [target, setTarget] = useState<api.Target | null>(null);
  const [current, setCurrent] = useState<Current>({ phase: "idle" });
  const [manual, setManual] = useState<Verdict | null>(null);
  const [detail, setDetail] = useState<{ v: Verdict; back: Screen } | null>(null);
  const scanned = useRef(false);

  // ── load everything from storage (and again whenever background.js changes it)
  const reload = useCallback(async () => {
    const [a, s, h] = await Promise.all([store.getAuth(), store.getSettings(), store.getHistory()]);
    setSettings(s);
    setHistory(h);
    setAuth(a);
    return a;
  }, []);

  useEffect(() => {
    (async () => {
      const a = await reload();
      if (!a) return setBoot("pair");
      if (!(await api.checkSession(a.token))) {
        setNotice("Your session ended. Generate a new pairing code in the desktop app.");
        return setBoot("pair");
      }
      setTarget(await api.currentTarget());
      setBoot("ready");
    })();
    return store.onStoreChange(async () => {
      const a = await reload();
      if (!a) setBoot("pair");
    });
  }, [reload]);

  // ── scanning the current page
  const scanCurrent = useCallback(async (force: boolean) => {
    if (!target) return;
    if (!target.scannable) return setCurrent({ phase: "idle" });
    setCurrent({ phase: "checking" });
    try {
      const verdict = await api.scan(target.url, { force, record: force, kind: "manual" });
      setCurrent({ phase: "done", verdict });
    } catch (e) {
      if (e instanceof api.ApiError && e.status === 401) {
        setNotice("Your session ended. Generate a new pairing code in the desktop app.");
        return setBoot("pair");
      }
      setCurrent({ phase: "error", message: (e as Error).message });
    }
  }, [target]);

  useEffect(() => {
    if (boot !== "ready" || !target || scanned.current) return;
    scanned.current = true;
    if (settings.realtime && settings.autoscan) scanCurrent(false);
  }, [boot, target, settings.realtime, settings.autoscan, scanCurrent]);

  // ── actions
  async function submitCode(code: string): Promise<string | null> {
    try {
      const a = await api.pair(code);
      setAuth(a);
      setNotice(undefined);
      setTarget(await api.currentTarget());
      scanned.current = false;
      setBoot("ready");
      return null;
    } catch (e) {
      return (e as Error).message;
    }
  }

  async function manualScan(raw: string): Promise<string | null> {
    let url = raw.trim();
    if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(url)) url = "https://" + url;
    try {
      const u = new URL(url);
      if (!/^https?:$/.test(u.protocol) || !u.hostname.includes(".")) throw new Error();
    } catch {
      return "That doesn't look like a valid website address.";
    }
    try {
      setManual(await api.scan(url, { force: true, record: true, kind: "manual" }));
      setScreen("manual_result");
      return null;
    } catch (e) {
      return (e as Error).message;
    }
  }

  async function goBackToSafety() {
    try {
      if (target?.tabId != null) {
        if (target.onWarningPage || (current.phase === "done" && current.verdict.status === "malicious")) {
          await chrome.tabs.update(target.tabId, { url: "chrome://newtab/" });
        } else {
          await chrome.tabs.goBack(target.tabId);
        }
      }
    } catch {
      if (target?.tabId != null) chrome.tabs.update(target.tabId, { url: "chrome://newtab/" });
    }
    window.close();
  }

  async function continueToSite(url: string) {
    await allowHost(url);
    if (target?.tabId != null && target.onWarningPage) await chrome.tabs.update(target.tabId, { url });
    window.close();
  }

  const openDetails = (v: Verdict, back: Screen) => { setDetail({ v, back }); setScreen("details"); };
  const goStatus = () => setScreen("status");

  // ── render
  if (boot === "loading") return <><Header /><div className="flex-1" /></>;
  if (boot === "pair") return <><Header /><PairScreen notice={notice} onSubmit={submitCode} /></>;

  const verdict = current.phase === "done" ? current.verdict : undefined;
  const recordedAt = verdict ? history.find((h) => h.url === verdict.url)?.ts : undefined;

  function statusView() {
    if (!settings.realtime) {
      return (
        <NoticeScreen icon="power" title="SafeBrowse is Disabled" text="Real-time protection is off. Your browsing is not being monitored."
          actions={[{ label: "Enable Protection", primary: true, onClick: async () => { await store.saveSettings({ ...settings, realtime: true }); scanned.current = false; setScreen("status"); setSettings({ ...settings, realtime: true }); scanCurrent(false); } }]} />
      );
    }
    if (target && !target.scannable) {
      return <NoticeScreen icon="info" title="This page isn't scanned" text="SafeBrowse checks public websites (http and https). Browser pages and local addresses are skipped." />;
    }
    switch (current.phase) {
      case "idle":
        return <NoticeScreen icon="info" title="Ready to scan" url={target?.url} text="Automatic scanning is off for this popup."
          actions={[{ label: "Scan This Page", primary: true, onClick: () => scanCurrent(true) }]} />;
      case "checking":
        return <CheckingScreen url={target?.url ?? ""} />;
      case "error":
        return <NoticeScreen icon="error" title="Couldn't check this page" text={current.message}
          actions={[{ label: "Try Again", primary: true, onClick: () => scanCurrent(false) }]} />;
      case "done": {
        const v = current.verdict;
        if (v.status === "safe")
          return <SafeScreen v={v} recordedAt={recordedAt} onViewDetails={() => openDetails(v, "status")} onScanAgain={() => scanCurrent(true)} onActivity={() => setScreen("activity")} />;
        if (v.status === "suspicious")
          return <SuspiciousScreen v={v} onBack={goBackToSafety} onViewDetails={() => openDetails(v, "status")} onContinue={() => window.close()} />;
        if (v.status === "malicious")
          return <MaliciousScreen v={v} blockingEnabled={settings.blocking} onWarningPage={!!target?.onWarningPage} onBack={goBackToSafety}
            onViewDetails={() => openDetails(v, "status")} onContinue={() => continueToSite(v.url)} />;
        return <NoticeScreen icon="info" title="No verdict yet" url={v.url}
          text="This site isn't flagged, but SafeBrowse has no data to confirm it is safe either."
          actions={[{ label: "View Details", onClick: () => openDetails(v, "status") }, { label: "Scan Again", primary: true, onClick: () => scanCurrent(true) }]} />;
      }
    }
  }

  function body() {
    switch (screen) {
      case "status": return statusView();
      case "activity": return <ActivityScreen current={verdict} history={history} monitoring={settings.realtime} onViewHistory={() => setScreen("history")} />;
      case "manual_scan": return <ManualScanScreen onScan={manualScan} />;
      case "manual_result": return manual ? <ManualResultScreen v={manual} onScanAnother={() => setScreen("manual_scan")} onViewDetails={() => openDetails(manual, "manual_result")} /> : null;
      case "history": return <HistoryScreen history={history} onViewDetails={(r) => openDetails(r, "history")} onClear={async () => { await store.clearHistory(); setHistory([]); }} />;
      case "settings": return <SettingsScreen settings={settings} email={auth?.user.email} onSave={async (s) => { await store.saveSettings(s); setSettings(s); }} onDisconnect={async () => { if (auth) await api.disconnect(auth.token); setNotice(undefined); setBoot("pair"); }} />;
      case "details": return detail ? <DetailsScreen v={detail.v} onBack={goStatus} /> : null;
    }
  }

  const subPage = screen === "settings" || screen === "details";
  const showNav = !subPage && !(screen === "status" && !settings.realtime);

  return (
    <>
      <Header
        showBack={subPage}
        title={screen === "settings" ? "Settings" : "Web Analysis"}
        onBack={() => setScreen(screen === "details" && detail ? detail.back : "status")}
        onSettings={subPage ? undefined : () => setScreen("settings")}
      />
      <div className="flex-1 overflow-y-auto">{body()}</div>
      {showNav && <Footer on={settings.realtime} />}
      {showNav && <NavBar screen={screen} onNav={setScreen} />}
    </>
  );
}
