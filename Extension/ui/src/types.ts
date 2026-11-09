export type Status = "safe" | "suspicious" | "malicious" | "unknown";

/** One source the detector asked (list, PhishTank, Safe Browsing, look-alike, domain age, AI 1, AI 2). */
export interface CheckItem {
  id: string;
  name: string;
  group: "list" | "api" | "rule" | "ai";
  state: "match" | "clear" | "info" | "unavailable" | "not_configured" | "skipped" | "no_opinion";
  detail: string;
  score: number | null;
  effect: "risk" | "trust" | "none";
}

/** One kind of page threat found by AI 2 (fake login, fake bank / payment, hidden download ...). */
export interface ThreatCategory {
  id: string;
  label: string;
  percent: number;
  level: "low" | "medium" | "high";
  triggered: boolean;
  description: string;
  evidence: string[];
}

export interface AiResult {
  name: string;
  state: "ok" | "no_opinion" | "skipped";
  percent: number | null; // phishing probability in percent (AI 1, AI 2)
  score: number | null; // risk score 0..100 this model contributes
  level: "none" | "low" | "elevated" | "high";
  description: string;
  categories?: ThreatCategory[];
  signals?: string[];
}

export interface Assessment {
  label: string;
  confidence: "high" | "medium" | "low";
  summary: string;
  supporting: string[];
  concerns: string[];
  not_checked: string[];
}

export interface FinalResult {
  assessment?: Assessment;
  status: string;
  score: number | null;
  list_api: { score: number | null; text: string };
  ai: { score: number | null; text: string };
  notes: string[];
  method: string;
  summary: string;
}

/** One answer from POST /analyze, normalised for the UI. */
export interface Verdict {
  url: string;
  status: Status;
  score: number;
  reasons: string[];
  source: string;
  adult: boolean; // backend status "Restricted" (adult-content block list)
  ts: number;
  scanId?: string | null; // the saved record in the account (lets "See more in app" open its detailed analysis)
  // structured parts of the detector result (absent when an older backend answered)
  checks?: CheckItem[];
  ai1?: AiResult;
  ai2?: AiResult;
  aiCombined?: AiResult;
  final?: FinalResult;
}

/** One row of the account's recent scans, read live from the server (never stored in the browser). */
export interface RecentScan {
  id: string;
  url: string;
  status: Status;
  score: number;
  ts: number;
}

export interface Settings {
  realtime: boolean; // master switch: check every page you open
  autoscan: boolean; // popup scans the current page by itself when opened
  blocking: boolean; // redirect malicious pages to the warning page
  notifications: boolean; // desktop notifications for suspicious pages
}

export interface Auth {
  token: string;
  user: { full_name?: string | null; email?: string | null };
  pairedAt: number;
}

/** What the person chose for one website (see chrome/siterules.js). */
export type SiteMode = "ask" | "once" | "hour" | "session" | "allow" | "block";
export interface SiteState {
  host: string;
  rule: "allow" | "block" | null; // saved to the account
  ruleHost: string | null; // the website the saved rule is for (a rule for example.com also covers a.example.com)
  hour: number | null; // when the 1-hour allowance ends
  session: boolean; // allowed until the browser closes
  once: boolean; // "just this visit"
  mode: SiteMode;
}
export interface SiteRule {
  id: string;
  host: string;
  rule: "allow" | "block";
  note: string | null;
  created_at: string;
}
