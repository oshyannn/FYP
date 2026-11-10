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
  /** administrator resetting an active account now (not a request) */
  reset_direct: boolean;
  /** another administrator's account: asking is allowed, a third administrator decides */
  request_deactivate: boolean;
  request_activate: boolean;
  request_delete: boolean;
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
  /** a request about this administrator account that is waiting for a third administrator */
  pending_change: { id: string; action: string; requested_by: string } | null;
  // only in the detail view
  email_verified?: boolean;
  last_login_at?: string | null;
  scan_count?: number;
}

export type InviteStatus = "awaiting_approval" | "sent" | "accepted" | "revoked" | "rejected" | "expired" | "locked";

export interface Invitation {
  id: string;
  email: string;
  full_name: string;
  role: "employer" | "admin";
  status: InviteStatus;
  invited_by: string;
  created_at: string;
  expires_at: string | null;
  accepted_at: string | null;
}

/** One line of the Approvals tab: a new administrator account, or a change to another administrator's account. */
export interface ApprovalItem {
  kind: "invitation" | "change";
  id: string;
  status: string;
  created_at: string;
  title: string;
  detail: string;
  requested_by: string;
  decided_by: string | null;
  can_decide: boolean;
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
const INVITE: Record<InviteStatus, [string, Tone]> = {
  awaiting_approval: ["Awaiting approval", "amber"],
  sent: ["Sent", "blue"],
  accepted: ["Accepted", "green"],
  revoked: ["Revoked", "slate"],
  rejected: ["Rejected", "red"],
  expired: ["Expired", "slate"],
  locked: ["Locked", "red"],
};
export const inviteLabel = (s: InviteStatus): string => INVITE[s]?.[0] ?? s;
export const inviteTone = (s: InviteStatus): Tone => INVITE[s]?.[1] ?? "slate";

/** The Approvals tab: one wording for invitations and for changes. */
export function approvalLabel(status: string): [string, Tone] {
  if (status === "pending" || status === "awaiting_approval") return ["Waiting", "amber"];
  if (status === "rejected") return ["Rejected", "red"];
  if (status === "cancelled") return ["Cancelled", "slate"];
  if (status === "accepted") return ["Approved · accepted", "green"];
  if (status === "expired" || status === "locked") return [`Approved · ${status}`, "slate"];
  return ["Approved", "green"];
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
  staff_invite_created: "Invited Staff Account",
  staff_invite_approved: "Approved Admin Invitation",
  staff_invite_rejected: "Rejected Admin Invitation",
  staff_invite_revoked: "Revoked Invitation",
  staff_invite_accepted: "Accepted Invitation",
  admin_change_requested: "Requested Admin Change",
  admin_change_approved: "Approved Admin Change",
  admin_change_rejected: "Rejected Admin Change",
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
