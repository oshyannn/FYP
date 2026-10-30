export type Status = "safe" | "suspicious" | "malicious" | "unknown";

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
