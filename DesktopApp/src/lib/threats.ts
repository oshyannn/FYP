import type { Level } from "./analysis";
import type { Tone } from "../components/Badge";

export type ThreatStatus = "active" | "pending_review" | "revoked";

export interface ThreatItem {
  id: string;
  url: string;
  domain: string;
  risk_level: Level;
  risk_score: number;
  threat_type: string;
  status: ThreatStatus;
  detection_count: number;
  created_at: string;
  last_verified_at: string;
}

export interface ThreatStats {
  total: number;
  phishing: number;
  malware: number;
  suspicious: number;
  pending?: number;
}

export const THREAT_TYPE_OPTIONS: [string, string][] = [
  ["phishing", "Phishing"],
  ["malware", "Malware"],
  ["scam", "Scam"],
  ["spam", "Spam"],
  ["defacement", "Defacement"],
  ["unwanted_software", "Unwanted software"],
  ["unknown", "Unclassified"],
];

export function threatTypeLabel(t: string): string {
  return THREAT_TYPE_OPTIONS.find(([v]) => v === t)?.[1] ?? t;
}
export function threatTypeTone(t: string): Tone {
  return t === "phishing" ? "orange" : t === "malware" ? "red" : "slate";
}
export function threatStatusLabel(s: string): string {
  return s === "active" ? "Active" : s === "pending_review" ? "Pending review" : s === "revoked" ? "Removed" : s;
}
export function threatStatusTone(s: string): Tone {
  return s === "active" ? "green" : s === "pending_review" ? "amber" : "slate";
}

export interface Application {
  id: string;
  name: string | null;
  email: string;
  company_name: string;
  company_registration_no: string;
  status: "pending" | "approved" | "rejected";
  remarks: string | null;
  submitted_at: string;
  reviewed_at: string | null;
  reviewed_by_name: string | null;
  role: string;
  account_status: string;
  email_verified: boolean;
}
export function applicationTone(s: string): Tone {
  return s === "approved" ? "green" : s === "rejected" ? "red" : "amber";
}
export function applicationLabel(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}
