import { useEffect, useState } from "react";
import { api } from "../../api";
import AppLayout from "../../components/layout/AppLayout";
import { USER_NAV } from "../../components/layout/nav";
import type { ScanRecord } from "../../lib/analysis";
import type { Session } from "../../types";
import Dashboard from "./Dashboard";
import Feedback from "./feedback/Feedback";
import DetailedAnalysis from "./scan/DetailedAnalysis";
import DetectionHistory from "./scan/DetectionHistory";
import Profile from "../shared/Profile";
import ThreatUrlList from "../shared/ThreatUrlList";
import ScanResult from "./scan/ScanResult";
import UrlScanner from "./scan/UrlScanner";

type Page = "dashboard" | "scanner" | "result" | "details" | "history" | "threats" | "feedback" | "profile";

interface Props {
  session: Session;
  onLogout: () => void;
}

const TITLES: Record<Page, string> = {
  dashboard: "Dashboard",
  scanner: "URL Scanner",
  result: "URL Scan Result",
  details: "Detailed Analysis",
  history: "Detection History",
  threats: "Threat URL List",
  feedback: "Feedback",
  profile: "Profile",
};

// The signed-in area for normal users. Screens are chosen here; each screen only gets what it needs.
export default function UserApp({ session, onLogout }: Props) {
  const [name, setName] = useState(session.user.full_name);
  const user = { ...session.user, full_name: name };
  const [page, setPage] = useState<Page>("dashboard");
  const [scan, setScan] = useState<ScanRecord | null>(null);
  const [cameFrom, setCameFrom] = useState<"result" | "history" | "dashboard">("history");
  const [reportScan, setReportScan] = useState<ScanRecord | null>(null);

  const report = (s: ScanRecord) => {
    setReportScan(s);
    setPage("feedback");
  };

  // the browser extension can open the app on a page (safebrowse://dashboard | history | scanner)
  useEffect(() => {
    const go = (p: string) => {
      if (p === "dashboard" || p === "history" || p === "scanner") {
        setReportScan(null);
        setPage(p);
      }
    };
    window.sb.takePendingPage().then((p) => p && go(p));
    return window.sb.onOpenPage(go);
  }, []);

  async function logout() {
    await api.post("/api/auth/logout");
    onLogout();
  }

  const active: string =
    page === "result" ? "scanner" : page === "details" ? (cameFrom === "result" ? "scanner" : cameFrom === "dashboard" ? "dashboard" : "history") : page;

  let content;
  if (page === "scanner") {
    content = (
      <UrlScanner
        onSessionEnd={onLogout}
        onScanned={(s) => {
          setScan(s);
          setPage("result");
        }}
      />
    );
  } else if (page === "result" && scan) {
    content = (
      <ScanResult
        scan={scan}
        onBack={() => setPage("scanner")}
        onDashboard={() => setPage("dashboard")}
        onReport={() => report(scan)}
        onDetails={() => {
          setCameFrom("result");
          setPage("details");
        }}
      />
    );
  } else if (page === "details" && scan) {
    content = (
      <DetailedAnalysis
        scan={scan}
        backLabel={cameFrom === "result" ? "Back to Result" : cameFrom === "dashboard" ? "Back to Dashboard" : "Back to Detection History"}
        onBack={() => setPage(cameFrom === "result" ? "result" : cameFrom === "dashboard" ? "dashboard" : "history")}
        onReport={() => report(scan)}
      />
    );
  } else if (page === "profile") {
    content = <Profile onSessionEnd={onLogout} onNameChanged={setName} />;
  } else if (page === "feedback") {
    content = <Feedback key={reportScan?.id ?? "none"} initialScan={reportScan} onSessionEnd={onLogout} />;
  } else if (page === "threats") {
    content = <ThreatUrlList onSessionEnd={onLogout} />;
  } else if (page === "history") {
    content = (
      <DetectionHistory
        onSessionEnd={onLogout}
        onOpen={(s) => {
          setScan(s);
          setCameFrom("history");
          setPage("details");
        }}
      />
    );
  } else {
    content = (
      <Dashboard
        name={user.full_name ?? user.email}
        onSessionEnd={onLogout}
        onViewAll={() => setPage("history")}
        onScanned={(s) => {
          setScan(s);
          setPage("result");
        }}
        onOpen={(s) => {
          setScan(s);
          setCameFrom("dashboard");
          setPage("details");
        }}
      />
    );
  }

  return (
    <AppLayout user={user} roleLabel="User" nav={USER_NAV} active={active} title={TITLES[page]} onNavigate={(id) => {
      setReportScan(null);
      setPage(id as Page);
    }} onLogout={logout}>
      {content}
    </AppLayout>
  );
}
