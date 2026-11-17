// Sidebar items per role. ready:false items are in the design and are built in later steps.
export interface NavItem {
  id: string;
  label: string;
  icon: string;
  ready: boolean;
}

// The threat lists (Threat feeds, Blocked, and the administrator-approved threats) live in Detection Lists,
// so there is no separate Threat URL List page for users.
export const USER_NAV: NavItem[] = [
  { id: "dashboard", label: "Dashboard", icon: "⊞", ready: true },
  { id: "scanner", label: "URL Scanner", icon: "⌕", ready: true },
  { id: "history", label: "Detection History", icon: "☰", ready: true },
  { id: "trusted", label: "Trusted Sites", icon: "✓", ready: true },
  { id: "lists", label: "Detection Lists", icon: "≡", ready: true },
  { id: "saved", label: "Saved URLs", icon: "★", ready: true },
  { id: "sites", label: "Site settings", icon: "⚙", ready: true },
  { id: "activity", label: "Browser Activity", icon: "◉", ready: true },
  { id: "feedback", label: "Feedback", icon: "✉", ready: true },
  { id: "profile", label: "Profile", icon: "◯", ready: true },
];

export const EMPLOYER_NAV: NavItem[] = [
  { id: "dashboard", label: "Dashboard", icon: "⊞", ready: true },
  { id: "threats", label: "Threat URL List", icon: "⚠", ready: true },
  { id: "users", label: "User Management", icon: "◯◯", ready: true },   // employer: users only (server enforces)
  { id: "approval", label: "URL Approval", icon: "✓", ready: true },
  { id: "lists", label: "Detection Lists", icon: "≡", ready: true },
  { id: "rules", label: "Detection Rules", icon: "⚑", ready: true },
  { id: "logs", label: "My Activity Logs", icon: "▤", ready: true },
  { id: "feedback", label: "User Feedback", icon: "✉", ready: true },
  { id: "profile", label: "Profile", icon: "◯", ready: true },
];

export const ADMIN_NAV: NavItem[] = [
  { id: "dashboard", label: "Dashboard", icon: "⊞", ready: true },
  { id: "employers", label: "Employer Verification", icon: "✓", ready: true },
  { id: "threats", label: "Threat URLs", icon: "⚠", ready: true },
  { id: "users", label: "User Management", icon: "◯◯", ready: true },
  { id: "approval", label: "URL Approval", icon: "⌕", ready: true },
  { id: "whitelist", label: "Trusted Sites", icon: "☰", ready: true },   // id kept: StaffApp routes on it
  { id: "lists", label: "Detection Lists", icon: "≡", ready: true },
  { id: "rules", label: "Detection Rules", icon: "⚑", ready: true },
  { id: "feedback", label: "User Feedback", icon: "✉", ready: true },
  { id: "logs", label: "Activity Logs", icon: "▤", ready: true },
  { id: "profile", label: "Profile", icon: "◯", ready: true },
];
