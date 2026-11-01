import { useState } from "react";
import type { AppState, Page, Role } from "./types";
import type { ThreatEntry, PendingSubmission } from "./threatStore";
import { initialThreats, initialPending } from "./threatStore";
import Layout from "./components/Layout";

import Login from "./pages/Login";
import Register from "./pages/Register";
import ForgotPassword from "./pages/ForgotPassword";
import UserDashboard from "./pages/UserDashboard";
import UrlScanner from "./pages/UrlScanner";
import ScanResult from "./pages/ScanResult";
import DetailedAnalysis from "./pages/DetailedAnalysis";
import DetectionHistory from "./pages/DetectionHistory";
import ThreatUrlList from "./pages/ThreatUrlList";
import Whitelist from "./pages/Whitelist";
import BrowserActivity from "./pages/BrowserActivity";
import Feedback from "./pages/Feedback";
import Profile from "./pages/Profile";
import Settings from "./pages/Settings";
import EmployerDashboard from "./pages/EmployerDashboard";
import UrlApproval from "./pages/UrlApproval";
import EmployerFeedback from "./pages/EmployerFeedback";
import AdminDashboard from "./pages/AdminDashboard";
import UserManagement from "./pages/UserManagement";
import EmployerVerification from "./pages/EmployerVerification";
import AdminThreatUrls from "./pages/AdminThreatUrls";
import ActivityLogs from "./pages/ActivityLogs";

const pageTitles: Record<Page, string> = {
  "login": "Login",
  "register": "Register",
  "forgot-password": "Forgot Password",
  "user-dashboard": "Dashboard",
  "url-scanner": "URL Scanner",
  "scan-result": "Scan Result",
  "detailed-analysis": "Detailed Analysis",
  "detection-history": "Detection History",
  "threat-url-list": "Threat URL List",
  "whitelist": "Trusted Websites",
  "browser-activity": "Browser Activity",
  "feedback": "Feedback",
  "profile": "Profile",
  "settings": "Settings",
  "employer-dashboard": "Employer Dashboard",
  "url-approval": "URL Approval",
  "employer-feedback": "Feedback Management",
  "admin-dashboard": "Admin Dashboard",
  "user-management": "User Management",
  "employer-verification": "Employer Verification",
  "admin-url-approval": "URL Approval",
  "admin-threat-urls": "Threat URL Management",
  "activity-logs": "Activity Logs",
  "admin-settings": "Settings",
};

const AUTH_PAGES: Page[] = ["login", "register", "forgot-password"];

let nextId = 200;

export default function App() {
  const [state, setState] = useState<AppState>({ page: "login", role: null });
  const [globalThreats, setGlobalThreats] = useState<ThreatEntry[]>(initialThreats);
  const [pendingSubmissions, setPendingSubmissions] = useState<PendingSubmission[]>(initialPending);

  const navigate = (page: Page, roleOrUrl?: Role | string, status?: string, score?: number) => {
    if (page === "login") { setState({ page: "login", role: null }); return; }
    if (page === "user-dashboard" || page === "employer-dashboard" || page === "admin-dashboard") {
      setState(s => ({ ...s, page, role: roleOrUrl as Role })); return;
    }
    if (roleOrUrl && typeof roleOrUrl === "string" && status) {
      setState(s => ({ ...s, page, scanUrl: roleOrUrl, scanStatus: status as any, scanScore: score })); return;
    }
    setState(s => ({ ...s, page }));
  };

  // Employer submits a new URL → goes to pending queue
  const submitThreatUrl = (entry: Omit<ThreatEntry, "id" | "date" | "status">) => {
    const sub: PendingSubmission = {
      id: nextId++,
      url: entry.url,
      type: entry.type,
      score: entry.score,
      notes: entry.notes,
      source: entry.source,
      submittedBy: "employer@safebrowse.com",
      submittedDate: new Date().toLocaleDateString("en-GB", { day: "2-digit", month: "short", year: "numeric" }) + ", " +
        new Date().toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit" }),
      reviewStatus: "Pending",
      reviewNote: "",
    };
    setPendingSubmissions(prev => [sub, ...prev]);
  };

  // Admin approves → publish to global threat list
  const approveThreatSubmission = (id: number, reviewNote: string) => {
    const sub = pendingSubmissions.find(s => s.id === id);
    if (!sub) return;
    const entry: ThreatEntry = {
      id: nextId++,
      url: sub.url,
      type: sub.type,
      score: sub.score,
      status: "Blocked",
      date: new Date().toLocaleDateString("en-GB", { day: "2-digit", month: "short", year: "numeric" }),
      source: sub.source,
      notes: sub.notes,
    };
    setGlobalThreats(prev => [entry, ...prev]);
    setPendingSubmissions(prev => prev.map(s => s.id === id ? { ...s, reviewStatus: "Approved", reviewNote } : s));
  };

  // Admin rejects
  const rejectThreatSubmission = (id: number, reviewNote: string) => {
    setPendingSubmissions(prev => prev.map(s => s.id === id ? { ...s, reviewStatus: "Rejected", reviewNote } : s));
  };

  // Admin directly removes from global list
  const removeThreatEntry = (id: number) => {
    setGlobalThreats(prev => prev.filter(t => t.id !== id));
  };

  const isAuth = AUTH_PAGES.includes(state.page);
  if (isAuth) {
    if (state.page === "login") return <Login navigate={(p, role) => navigate(p, role)} />;
    if (state.page === "register") return <Register navigate={navigate} />;
    if (state.page === "forgot-password") return <ForgotPassword navigate={navigate} />;
  }

  const title = pageTitles[state.page] || "SafeBrowse";

  const renderPage = () => {
    switch (state.page) {
      case "user-dashboard":
        return <UserDashboard navigate={(p, url, status, score) => navigate(p, url, status, score)} />;
      case "url-scanner":
        return <UrlScanner navigate={(p, url, status, score) => navigate(p, url, status, score)} />;
      case "scan-result":
        return <ScanResult navigate={(p, url, status, score) => navigate(p, url, status, score)} url={state.scanUrl} status={state.scanStatus} score={state.scanScore} />;
      case "detailed-analysis":
        return <DetailedAnalysis navigate={navigate} url={state.scanUrl} status={state.scanStatus} score={state.scanScore} />;
      case "detection-history":
        return <DetectionHistory navigate={(p, url, status, score) => navigate(p, url, status, score)} />;
      case "threat-url-list":
        return (
          <ThreatUrlList
            role={state.role}
            threats={globalThreats}
            mySubmissions={pendingSubmissions.filter(s => s.submittedBy === "employer@safebrowse.com")}
            onSubmit={submitThreatUrl}
          />
        );
      case "whitelist":
        return <Whitelist />;
      case "browser-activity":
        return <BrowserActivity navigate={(p, url, status, score) => navigate(p, url, status, score)} />;
      case "feedback":
        return <Feedback />;
      case "profile":
        return <Profile role={state.role} />;
      case "settings":
      case "admin-settings":
        return <Settings />;
      case "employer-dashboard":
        return <EmployerDashboard navigate={navigate} />;
      case "url-approval":
        return <UrlApproval />;
      case "admin-url-approval":
        return (
          <UrlApproval
            pendingThreats={pendingSubmissions}
            onApproveThreat={approveThreatSubmission}
            onRejectThreat={rejectThreatSubmission}
          />
        );
      case "employer-feedback":
        return <EmployerFeedback />;
      case "admin-dashboard":
        return <AdminDashboard navigate={navigate} pendingCount={pendingSubmissions.filter(s => s.reviewStatus === "Pending").length} />;
      case "user-management":
        return <UserManagement />;
      case "employer-verification":
        return <EmployerVerification />;
      case "admin-threat-urls":
        return <AdminThreatUrls threats={globalThreats} onRemove={removeThreatEntry} />;
      case "activity-logs":
        return <ActivityLogs />;
      default:
        return <UserDashboard navigate={(p, url, status, score) => navigate(p, url, status, score)} />;
    }
  };

  return (
    <Layout state={state} navigate={navigate} title={title}>
      {renderPage()}
    </Layout>
  );
}
