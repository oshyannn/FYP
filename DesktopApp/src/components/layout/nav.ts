// Sidebar items per role. ready:false items are in the design and are built in later steps.
export interface NavItem {
  id: string;
  label: string;
  icon: string;
  ready: boolean;
}

export const USER_NAV: NavItem[] = [
  { id: "dashboard", label: "Dashboard", icon: "⊞", ready: true },
  { id: "scanner", label: "URL Scanner", icon: "⌕", ready: true },
  { id: "history", label: "Detection History", icon: "☰", ready: true },
  { id: "threats", label: "Threat URL List", icon: "⚠", ready: true },
  { id: "whitelist", label: "Whitelist", icon: "✓", ready: false },
  { id: "activity", label: "Browser Activity", icon: "◉", ready: false },
  { id: "feedback", label: "Feedback", icon: "✉", ready: true },
  { id: "profile", label: "Profile", icon: "◯", ready: true },
];

export const EMPLOYER_NAV: NavItem[] = [
  { id: "dashboard", label: "Dashboard", icon: "⊞", ready: true },
  { id: "threats", label: "Threat URL List", icon: "⚠", ready: true },
  { id: "approval", label: "URL Approval", icon: "✓", ready: false },
  { id: "feedback", label: "User Feedback", icon: "✉", ready: true },
  { id: "profile", label: "Profile", icon: "◯", ready: true },
];

export const ADMIN_NAV: NavItem[] = [
  { id: "dashboard", label: "Dashboard", icon: "⊞", ready: true },
  { id: "employers", label: "Employer Verification", icon: "✓", ready: true },
  { id: "threats", label: "Threat URLs", icon: "⚠", ready: true },
  { id: "users", label: "User Management", icon: "◯◯", ready: false },
  { id: "approval", label: "URL Approval", icon: "⌕", ready: false },
  { id: "whitelist", label: "Whitelist", icon: "☰", ready: false },
  { id: "feedback", label: "User Feedback", icon: "✉", ready: true },
  { id: "logs", label: "Activity Logs", icon: "▤", ready: false },
  { id: "profile", label: "Profile", icon: "◯", ready: true },
];
