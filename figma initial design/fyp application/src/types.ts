export type Role = "user" | "employer" | "admin";

export type Page =
  | "login"
  | "register"
  | "forgot-password"
  | "user-dashboard"
  | "url-scanner"
  | "scan-result"
  | "detailed-analysis"
  | "detection-history"
  | "threat-url-list"
  | "whitelist"
  | "browser-activity"
  | "feedback"
  | "profile"
  | "settings"
  | "employer-dashboard"
  | "url-approval"
  | "employer-feedback"
  | "admin-dashboard"
  | "user-management"
  | "employer-verification"
  | "admin-url-approval"
  | "admin-threat-urls"
  | "activity-logs"
  | "admin-settings";

export interface AppState {
  page: Page;
  role: Role | null;
  scanUrl?: string;
  scanStatus?: "SAFE" | "SUSPICIOUS" | "MALICIOUS";
  scanScore?: number;
}
