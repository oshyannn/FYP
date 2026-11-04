// Types and labels for User Management and Activity Logs (employers and administrators).
import type { Tone } from "../components/Badge";
import { shortDate } from "./approvals";

export type AccountStatus = "active" | "inactive" | "pending" | "deleted";
export type StaffRole = "employer" | "admin";

/** What the signed-in person may do with an account. The server decides; the screen only shows what is true. */
export interface AccountActions {
  edit: boolean;
  deactivate: boolean;
  activate: boolean;
  delete: boolean;
  reset_password: boolean;
}

export interface AdminUser {
  id: string;
  full_name: string | null;
  email: string;
  role: "user" | "employer" | "admin";
  status: AccountStatus;
  created_at: string;
  is_self: boolean;
  actions: AccountActions;
  // only in the detail view
  email_verified?: boolean;
  last_login_at?: string | null;
  scan_count?: number;
}

export interface ActivityRow {
  actor: string;
  actor_role: "admin" | "employer";
  action: string;
  module: string;
  target: string;
  created_at: string;
  status: string;
}

export const displayName = (u: Pick<AdminUser, "full_name" | "email">): string => u.full_name || u.email;

export function accountStatusLabel(s: AccountStatus): string {
  return s === "active" ? "Active" : s === "pending" ? "Pending" : s === "deleted" ? "Deleted" : "Inactive";
}
export function accountStatusTone(s: AccountStatus): Tone {
  return s === "active" ? "green" : s === "pending" ? "amber" : s === "deleted" ? "slate" : "red";
}
export const roleLabel = (r: string): string => (r === "employer" ? "Employer" : r === "admin" ? "Admin" : r === "user" ? "User" : r);
export const roleTone = (r: string): Tone => (r === "admin" ? "blue" : r === "employer" ? "orange" : "slate");

const ACTIONS: Record<string, string> = {
  employer_approved: "Verified Employer",
  employer_rejected: "Rejected Employer",
  threat_approve: "Approved URL",
  threat_remove: "Removed URL",
  threat_submission_create: "Submitted Threat URL",
  threat_submission_approve: "Approved Threat Submission",
  threat_submission_reject: "Rejected Threat Submission",
  whitelist_add: "Added to Whitelist",
  whitelist_remove: "Removed from Whitelist",
  whitelist_request_approve: "Approved Whitelist Request",
  whitelist_request_reject: "Rejected Whitelist Request",
  user_activated: "Activated User",
  user_deactivated: "Deactivated User",
  user_updated: "Edited User",
  user_deleted: "Deleted User",
  user_password_reset_sent: "Sent Password Reset",
  feedback_replied: "Replied to Feedback",
  feedback_in_progress: "Marked Feedback In Review",
  feedback_resolved: "Resolved Feedback",
  feedback_closed: "Closed Feedback",
};

/** "user_deactivated" -> "Deactivated User". Unknown actions are shown readable instead of hidden. */
export function actionLabel(action: string): string {
  if (ACTIONS[action]) return ACTIONS[action];
  const words = action.replace(/_/g, " ").trim();
  return words ? words.charAt(0).toUpperCase() + words.slice(1) : "—";
}

/** "31 Aug 2026 10:30" */
export function logDateTime(iso: string): string {
  const t = new Date(iso).toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit", hour12: false });
  return `${shortDate(iso)} ${t}`;
}

export const USERS_PER_PAGE = 10;
export const LOGS_PER_PAGE = 20;
