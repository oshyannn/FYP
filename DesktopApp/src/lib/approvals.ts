// Types and labels for the Whitelist and URL Approval screens (whitelist requests and threat submissions).
import type { Tone } from "../components/Badge";
import type { Level } from "./analysis";

export type ReviewStatus = "pending" | "approved" | "rejected";

export interface WhitelistEntry {
  id: string;
  domain: string;
  scope: "user" | "global";
  added_at: string;
  added_by: string;
}

export interface WhitelistRequest {
  id: string;
  domain: string;
  reason: string | null;
  risk_score: number | null; // null = the detector had no data
  risk_level: Level;
  status: ReviewStatus;
  review_note: string | null;
  created_at: string;
  reviewed_at: string | null;
  requester?: string; // staff only
  requester_email?: string;
  reviewed_by_name?: string | null;
}

export type SubmissionCategory = "phishing" | "malware" | "suspicious" | "spam" | "scam";

export interface ThreatSubmission {
  id: string;
  url: string;
  domain: string;
  category: SubmissionCategory;
  risk_score: number;
  notes: string;
  status: ReviewStatus;
  review_note: string | null;
  created_at: string;
  reviewed_at: string | null;
  submitted_by?: string; // admin only
  submitted_by_email?: string;
  reviewed_by_name?: string | null;
}

export const SUBMISSION_CATEGORIES: [SubmissionCategory, string][] = [
  ["phishing", "Phishing"],
  ["malware", "Malware"],
  ["suspicious", "Suspicious"],
  ["spam", "Spam"],
  ["scam", "Scam"],
];

export function categoryLabel(c: string): string {
  return SUBMISSION_CATEGORIES.find(([v]) => v === c)?.[1] ?? c;
}
export function categoryTone(c: string): Tone {
  return c === "phishing" ? "orange" : c === "malware" ? "red" : c === "suspicious" ? "amber" : "slate";
}

export function reviewLabel(s: string): string {
  return s === "approved" ? "Approved" : s === "rejected" ? "Rejected" : "Pending";
}
export function reviewTone(s: string): Tone {
  return s === "approved" ? "green" : s === "rejected" ? "red" : "amber";
}

/** The colour the design uses for a 0-100 risk score. */
export function scoreClass(score: number): string {
  return score < 30 ? "text-green-600" : score < 70 ? "text-amber-600" : "text-red-600";
}
export function scoreBarClass(score: number): string {
  return score < 30 ? "bg-green-500" : score < 70 ? "bg-amber-500" : "bg-red-500";
}

export function shortDate(iso: string): string {
  return new Date(iso).toLocaleDateString("en-GB", { day: "2-digit", month: "short", year: "numeric" });
}
export function shortDateTime(iso: string): string {
  return `${shortDate(iso)}, ${new Date(iso).toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit" })}`;
}

export const WHITELIST_PER_PAGE = 50;
export const REVIEW_PER_PAGE = 10;
