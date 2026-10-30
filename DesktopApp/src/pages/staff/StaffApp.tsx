import { useState } from "react";
import { api } from "../../api";
import AppLayout from "../../components/layout/AppLayout";
import { ADMIN_NAV, EMPLOYER_NAV } from "../../components/layout/nav";
import type { Session } from "../../types";
import Profile from "../shared/Profile";
import ThreatUrlList from "../shared/ThreatUrlList";
import EmployerVerification from "./EmployerVerification";
import StaffFeedback from "../StaffFeedback";
import StaffDashboard from "./StaffDashboard";

interface Props {
  session: Session;
  onLogout: () => void;
}

const TITLES: Record<string, string> = {
  dashboard: "Dashboard",
  employers: "Employer Verification",
  threats: "Threat URL Management",
  feedback: "User Feedback",
  profile: "Profile",
};

// The signed-in area for employers and administrators.
export default function StaffApp({ session, onLogout }: Props) {
  const [name, setName] = useState(session.user.full_name);
  const user = { ...session.user, full_name: name };
  const admin = user.role === "admin";
  const role: "employer" | "admin" = admin ? "admin" : "employer";
  const [page, setPage] = useState("dashboard");

  async function logout() {
    await api.post("/api/auth/logout");
    onLogout();
  }

  let content;
  if (page === "employers" && admin) content = <EmployerVerification onSessionEnd={onLogout} />;
  else if (page === "profile") content = <Profile onSessionEnd={onLogout} onNameChanged={setName} />;
  else if (page === "feedback") content = <StaffFeedback onSessionEnd={onLogout} />;
  else if (page === "threats") content = <ThreatUrlList staffRole={role} onSessionEnd={onLogout} />;
  else content = <StaffDashboard role={role} name={user.full_name ?? user.email} onNavigate={setPage} onSessionEnd={onLogout} />;

  return (
    <AppLayout
      user={user}
      roleLabel={admin ? "Admin" : "Employer"}
      nav={admin ? ADMIN_NAV : EMPLOYER_NAV}
      active={page}
      title={TITLES[page] ?? "Dashboard"}
      tone="staff"
      onNavigate={setPage}
      onLogout={logout}
    >
      {content}
    </AppLayout>
  );
}
