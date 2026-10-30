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
