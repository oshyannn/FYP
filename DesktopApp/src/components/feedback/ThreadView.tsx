import type { ReactNode } from "react";
import Badge from "./Badge";
import StatusBadge from "../StatusBadge";
import { LEVEL_STYLE, reasonsOf, scoreText } from "../../lib/analysis";
import { categoryLabel, statusLabel, statusTone } from "../../lib/feedback";
import type { FeedbackThread } from "../../lib/feedback";

interface Props {
  thread: FeedbackThread;
  staff?: boolean;
  actions?: ReactNode;
  footer?: ReactNode;
}

const ROLE_LABEL = { user: "User", employer: "Employer", admin: "Admin" } as const;
const ROLE_STYLE = { user: "bg-slate-200 text-slate-700", employer: "bg-amber-100 text-amber-800", admin: "bg-[#1e3a5f] text-white" } as const;

function initials(name: string | null | undefined) {
  const parts = (name ?? "?").trim().split(/\s+/).filter(Boolean);
  return ((parts[0]?.[0] ?? "?") + (parts.length > 1 ? parts[parts.length - 1][0] : "")).toUpperCase();
}

export default function ThreadView({ thread, staff, actions, footer }: Props) {
  const scan = thread.attached_scan;
  const findings = reasonsOf(scan?.analysis);
  return (
    <div className="space-y-5">
      <div className="bg-white rounded-xl border border-slate-200 p-5">
        <div className="flex items-start justify-between gap-4 flex-wrap">
          <div className="min-w-0">
            <h2 className="text-lg font-semibold text-slate-900 leading-snug break-words">{thread.subject}</h2>
            <div className="flex items-center gap-2 mt-2 flex-wrap text-xs text-slate-500">
              <Badge tone="slate">{categoryLabel(thread.category)}</Badge>
              <Badge tone={statusTone(thread.status)}>{statusLabel(thread.status)}</Badge>
              <span>{new Date(thread.created_at).toLocaleString()}</span>
              {staff && thread.author_email && (
                <span>
                  · from {thread.author_name ?? "—"} ({thread.author_email})
                </span>
              )}
            </div>
          </div>
          {actions && <div className="flex gap-2 flex-wrap">{actions}</div>}
        </div>
        <p className="mt-4 text-sm text-slate-700 whitespace-pre-wrap break-words">{thread.message}</p>

        {scan && (
          <div className="mt-4 rounded-lg border border-slate-200 bg-slate-50 p-4">
            <p className="text-xs font-medium text-slate-500 mb-2">Attached scan result</p>
            <p className="text-xs font-mono text-slate-800 break-all">{scan.url}</p>
            <div className="flex items-center gap-3 mt-2 text-xs text-slate-600 flex-wrap">
              <StatusBadge level={scan.risk_level} />
              <span className={`font-semibold ${LEVEL_STYLE[scan.risk_level].text}`}>{scoreText(scan)}</span>
              <span>scanned {new Date(scan.scanned_at).toLocaleString()}</span>
            </div>
            {findings.length > 0 && (
              <ul className="list-disc pl-5 mt-3 space-y-0.5 text-xs text-slate-600">
                {findings.map((f, i) => (
                  <li key={i}>{f}</li>
                ))}
              </ul>
            )}
          </div>
        )}
        {thread.resolved_at && (
          <p className="mt-3 text-xs text-slate-500">
            {thread.status === "closed" ? "Closed" : "Resolved"} {new Date(thread.resolved_at).toLocaleString()}
            {thread.resolved_by_name ? ` by ${thread.resolved_by_name}` : ""}
          </p>
        )}
      </div>

      {thread.replies.length > 0 && (
        <div className="space-y-3" aria-label="Replies">
          {thread.replies.map((r) => (
            <div key={r.id} className="flex gap-3">
              <div className={`w-8 h-8 rounded-full shrink-0 text-xs font-semibold flex items-center justify-center ${ROLE_STYLE[r.author_role]}`}>
                {initials(r.author_name)}
              </div>
              <div className="flex-1 bg-white rounded-xl border border-slate-200 p-4 min-w-0">
                <div className="flex items-center gap-2 text-xs text-slate-500 mb-1">
                  <span className="font-medium text-slate-800">{r.author_name ?? "—"}</span>
                  <span>{ROLE_LABEL[r.author_role]}</span>
                  <span>· {new Date(r.created_at).toLocaleString()}</span>
                </div>
                <p className="text-sm text-slate-700 whitespace-pre-wrap break-words">{r.message}</p>
              </div>
            </div>
          ))}
        </div>
      )}
      {footer}
    </div>
  );
}
