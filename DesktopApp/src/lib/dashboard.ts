import type { Level } from "./analysis";

export interface UserStats {
  total: number;
  safe: number;
  suspicious: number;
  malicious: number;
  unknown: number;
}

export interface StaffSummary {
  role: "employer" | "admin";
  stats: {
    total_scans: number;
    active_threats: number;
    pending_threats: number;
    open_feedback: number;
    total_users?: number; // admin only
    total_employers?: number;
    pending_employers?: number;
  };
  distribution: { safe: number; suspicious: number; malicious: number; unknown: number };
  waiting: { id: string; url: string; risk_level: Level; risk_score: number; threat_type: string; last_verified_at: string }[];
  activity: { action: string; module: string; actor: string | null; created_at: string }[] | null;
}

const ACTIVITY: Record<string, string> = {
  employer_approved: "Approved an employer application",
  employer_rejected: "Rejected an employer application",
  threat_approve: "Approved a detected URL",
  threat_remove: "Removed or rejected a detected URL",
  feedback_replied: "Replied to feedback",
  feedback_in_progress: "Marked feedback in review",
  feedback_resolved: "Marked feedback resolved",
  feedback_closed: "Closed feedback",
};
export function activityText(action: string): string {
  return ACTIVITY[action] ?? action.replace(/_/g, " ");
}

export function percent(n: number, total: number): number {
  return total > 0 ? Math.round((n / total) * 100) : 0;
}
