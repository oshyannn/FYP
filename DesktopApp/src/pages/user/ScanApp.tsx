import { useState } from "react";
import type { ScanRecord } from "../../lib/analysis";
import DetailedAnalysis from "./scan/DetailedAnalysis";
import DetectionHistory from "./scan/DetectionHistory";
import ScanResult from "./scan/ScanResult";
import UrlScanner from "./scan/UrlScanner";

type Tab = "scanner" | "history";
type Screen = "tab" | "result" | "details";

interface Props {
  onBack: () => void;
  onLogout: () => void;
  /** "Report wrong detection": the home screen opens Feedback with this scan attached */
  onReport: (scan: ScanRecord) => void;
  /** which tab to show first (the browser extension can link straight to the detection history) */
  initialTab?: Tab;
}

// The scanner area of the desktop app: URL Scanner, its result, the detailed analysis and the detection history.
export default function ScanApp({ onBack, onLogout, onReport, initialTab }: Props) {
  const [tab, setTab] = useState<Tab>(initialTab ?? "scanner");
  const [screen, setScreen] = useState<Screen>("tab");
  const [scan, setScan] = useState<ScanRecord | null>(null);
  const [cameFrom, setCameFrom] = useState<"result" | "history">("history");
  const [notice, setNotice] = useState("");

  const showTab = (t: Tab) => {
    setTab(t);
    setScreen("tab");
    setNotice("");
  };

  const report = () => {
    if (scan) onReport(scan);
  };

  let content;
  if (screen === "result" && scan) {
    content = (
      <ScanResult
        scan={scan}
        onBack={() => showTab("scanner")}
        onDashboard={() => showTab("history")}
        onDetails={() => {
          setCameFrom("result");
          setScreen("details");
        }}
        onReport={report}
      />
    );
  } else if (screen === "details" && scan) {
    content = (
      <DetailedAnalysis
        scan={scan}
        backLabel={cameFrom === "result" ? "Back to Result" : "Back to Detection History"}
        onBack={() => (cameFrom === "result" ? setScreen("result") : showTab("history"))}
        onReport={report}
      />
    );
  } else if (tab === "scanner") {
    content = (
      <UrlScanner
        onScanned={(s) => {
          setScan(s);
          setScreen("result");
        }}
        onSessionEnd={onLogout}
      />
    );
  } else {
    content = (
      <DetectionHistory
        onSessionEnd={onLogout}
        onOpen={(s) => {
          setScan(s);
          setCameFrom("history");
          setScreen("details");
        }}
      />
    );
  }

  const tabCls = (t: Tab) =>
    `px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
      tab === t ? "bg-[#1e3a5f] text-white" : "text-slate-600 hover:bg-slate-100"
    }`;

  return (
    <div className="h-full overflow-y-auto bg-slate-50">
      <header className="bg-[#1e3a5f] text-white">
        <div className="max-w-6xl mx-auto px-6 py-4 flex items-center justify-between">
          <h1 className="text-lg font-bold">SafeBrowse</h1>
          <button onClick={onBack} className="text-sm border border-white/30 rounded-lg px-3 py-1.5 hover:bg-white/10">
            Back to home
          </button>
        </div>
      </header>

      <main className="max-w-6xl mx-auto px-6 py-8 space-y-6">
        {screen === "tab" && (
          <nav className="flex gap-2">
            <button onClick={() => showTab("scanner")} className={tabCls("scanner")}>
              URL Scanner
            </button>
            <button onClick={() => showTab("history")} className={tabCls("history")}>
              Detection History
            </button>
          </nav>
        )}
        {notice && <p className="text-sm text-slate-600 bg-white border border-slate-200 rounded-lg px-4 py-2">{notice}</p>}
        {content}
      </main>
    </div>
  );
}
