import type { Tone } from "../components/feedback/Badge";
import type { ApiResult } from "../types";
import type { Analysis, Level } from "./analysis";

export type FeedbackStatus = "open" | "in_progress" | "resolved" | "closed";
export type FeedbackCategory = "false_positive" | "false_negative" | "bug_report" | "suggestion" | "other";

export interface FeedbackRow {
  id: string;
  category: FeedbackCategory;
  subject: string;
  status: FeedbackStatus;
  created_at: string;
  updated_at: string;
  has_scan: boolean;
  reply_count: number;
  last_reply_at: string | null;
  author_name: string | null;
  author_email: string;
}

export interface FeedbackReply {
  id: string;
  message: string;
  created_at: string;
  author_name: string | null;
  author_role: "user" | "employer" | "admin";
}

export interface AttachedScan {
  id: string;
  url: string;
  domain: string;
  risk_level: Level;
  risk_score: number;
  scanned_at: string;
  analysis?: Analysis;
}

export interface FeedbackThread {
  id: string;
  category: FeedbackCategory;
  subject: string;
  message: string;
  status: FeedbackStatus;
  created_at: string;
  updated_at: string;
  resolved_at: string | null;
  resolved_by_name: string | null;
  can_edit: boolean;
  can_reply: boolean;
  attached_scan: AttachedScan | null;
  replies: FeedbackReply[];
  author_name?: string | null; // staff view only
  author_email?: string;
}

export const CATEGORY_OPTIONS: [FeedbackCategory, string][] = [
  ["false_positive", "False positive: a safe site was flagged"],
  ["false_negative", "False negative: a threat was missed"],
  ["bug_report", "Bug report"],
  ["suggestion", "Suggestion"],
  ["other", "Other"],
];

const CATEGORY_SHORT: Record<string, string> = {
  false_positive: "False Positive",
  false_negative: "False Negative",
  bug_report: "Bug Report",
  suggestion: "Suggestion",
  other: "Other",
};
export const categoryLabel = (c: string) => CATEGORY_SHORT[c] ?? c;

export const STATUS_OPTIONS: [FeedbackStatus, string][] = [
  ["open", "Open"],
  ["in_progress", "In Review"],
  ["resolved", "Resolved"],
  ["closed", "Closed"],
];
export const statusLabel = (s: string) => STATUS_OPTIONS.find(([v]) => v === s)?.[1] ?? s;
export function statusTone(s: string): Tone {
  return s === "open" ? "blue" : s === "in_progress" ? "amber" : s === "resolved" ? "green" : "slate";
}

/** A sensible starting type when the user reports a scan result as wrong. */
export function categoryForScan(level: Level): FeedbackCategory {
  return level === "safe" || level === "unknown" ? "false_negative" : "false_positive";
}

/** PATCH through the Electron bridge (api.ts only has get/post/del, and this keeps api.ts untouched). */
export const patchFeedback = (path: string, body?: unknown): Promise<ApiResult> => window.sb.api("PATCH", path, body);
