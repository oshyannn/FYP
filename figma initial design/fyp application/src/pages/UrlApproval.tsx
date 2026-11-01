import { useState } from "react";
import StatusBadge from "../components/StatusBadge";
import type { PendingSubmission } from "../threatStore";

// Existing whitelist-style URL approval requests (kept for employer view)
const whitelistRequests = [
  { id: 1, url: "company-portal.com", by: "john@email.com", date: "31 Aug 2026", score: 24, status: "Pending", reason: "Internal company portal" },
  { id: 2, url: "partner-site.org", by: "sarah@email.com", date: "30 Aug 2026", score: 41, status: "Pending", reason: "Trusted partner website" },
  { id: 3, url: "vendor-login.com", by: "mike@email.com", date: "30 Aug 2026", score: 58, status: "Pending", reason: "Vendor access portal" },
  { id: 4, url: "approved-tool.io", by: "anna@email.com", date: "29 Aug 2026", score: 12, status: "Approved", reason: "Dev tool" },
];

interface Props {
  pendingThreats?: PendingSubmission[];
  onApproveThreat?: (id: number, note: string) => void;
  onRejectThreat?: (id: number, note: string) => void;
}

export default function UrlApproval({ pendingThreats = [], onApproveThreat, onRejectThreat }: Props) {
  const isAdmin = !!onApproveThreat;

  // Tabs: admin sees both; employer sees only whitelist requests
  const [activeTab, setActiveTab] = useState<"whitelist" | "threats">(isAdmin ? "threats" : "whitelist");

  // Whitelist requests state
  const [wlItems, setWlItems] = useState(whitelistRequests);
  const [wlSelected, setWlSelected] = useState<typeof whitelistRequests[0] | null>(null);
  const [wlConfirm, setWlConfirm] = useState<{ action: "approve" | "reject"; id: number } | null>(null);

  // Threat submission state
  const [threatSelected, setThreatSelected] = useState<PendingSubmission | null>(null);
  const [reviewNote, setReviewNote] = useState("");
  const [confirmAction, setConfirmAction] = useState<"approve" | "reject" | null>(null);

  const handleWl = (action: "approve" | "reject", id: number) => {
    setWlItems(prev => prev.map(it => it.id === id ? { ...it, status: action === "approve" ? "Approved" : "Rejected" } : it));
    setWlConfirm(null);
    setWlSelected(null);
  };

  const handleThreat = (action: "approve" | "reject") => {
    if (!threatSelected) return;
    if (action === "approve") onApproveThreat?.(threatSelected.id, reviewNote);
    else onRejectThreat?.(threatSelected.id, reviewNote);
    setThreatSelected(null);
    setReviewNote("");
    setConfirmAction(null);
  };

  const pendingCount = pendingThreats.filter(s => s.reviewStatus === "Pending").length;
  const scoreColor = (s: number) => s < 30 ? "text-green-600" : s < 70 ? "text-amber-600" : "text-red-600";

  const statusStyle = (s: string) =>
    s === "Approved" ? "bg-green-50 text-green-700 border-green-200"
    : s === "Rejected" ? "bg-red-50 text-red-700 border-red-200"
    : "bg-amber-50 text-amber-700 border-amber-200";

  return (
    <div className="max-w-5xl space-y-5">
      <div>
        <h2 className="text-xl font-bold text-slate-900">URL Approval</h2>
        <p className="text-slate-500 text-sm mt-0.5">Review and act on pending URL requests.</p>
      </div>

      {/* Tabs */}
      <div className="flex border-b border-slate-200">
        {isAdmin && (
          <button onClick={() => setActiveTab("threats")}
            className={`flex items-center gap-2 px-4 py-2.5 text-sm font-medium border-b-2 transition-colors ${activeTab === "threats" ? "border-[#1e3a5f] text-[#1e3a5f]" : "border-transparent text-slate-500 hover:text-slate-700"}`}>
            Threat URL Submissions
            {pendingCount > 0 && (
              <span className="bg-amber-500 text-white text-[10px] font-bold px-1.5 py-0.5 rounded-full">{pendingCount}</span>
            )}
          </button>
        )}
        <button onClick={() => setActiveTab("whitelist")}
          className={`flex items-center gap-2 px-4 py-2.5 text-sm font-medium border-b-2 transition-colors ${activeTab === "whitelist" ? "border-[#1e3a5f] text-[#1e3a5f]" : "border-transparent text-slate-500 hover:text-slate-700"}`}>
          Whitelist Requests
          {wlItems.filter(i => i.status === "Pending").length > 0 && (
            <span className="bg-amber-500 text-white text-[10px] font-bold px-1.5 py-0.5 rounded-full">
              {wlItems.filter(i => i.status === "Pending").length}
            </span>
          )}
        </button>
      </div>

      {/* ── Threat URL Submissions Tab ── */}
      {activeTab === "threats" && (
        <>
          {/* Summary cards */}
          <div className="grid grid-cols-3 gap-4">
            {[
              { label: "Total Submissions", value: pendingThreats.length, color: "text-slate-800", bg: "bg-slate-50" },
              { label: "Pending Review", value: pendingThreats.filter(s => s.reviewStatus === "Pending").length, color: "text-amber-600", bg: "bg-amber-50" },
              { label: "Reviewed", value: pendingThreats.filter(s => s.reviewStatus !== "Pending").length, color: "text-green-600", bg: "bg-green-50" },
            ].map(s => (
              <div key={s.label} className={`${s.bg} rounded-xl border border-slate-200 p-4 text-center`}>
                <div className={`text-2xl font-bold ${s.color}`}>{s.value}</div>
                <div className="text-slate-500 text-xs mt-1">{s.label}</div>
              </div>
            ))}
          </div>

          <div className="bg-white rounded-xl border border-slate-200 overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="text-xs text-slate-500 bg-slate-50 border-b border-slate-200">
                    {["URL", "Type", "Risk Score", "Submitted By", "Submitted Date", "Status", "Action"].map(h => (
                      <th key={h} className="text-left px-5 py-3 font-medium">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {pendingThreats.length === 0 && (
                    <tr><td colSpan={7} className="px-5 py-10 text-center text-slate-400 text-sm">No threat URL submissions yet.</td></tr>
                  )}
                  {pendingThreats.map(sub => (
                    <tr key={sub.id} className="hover:bg-slate-50 transition-colors">
                      <td className="px-5 py-3.5 text-sm font-mono text-slate-700">{sub.url}</td>
                      <td className="px-5 py-3.5"><StatusBadge status={sub.type} /></td>
                      <td className="px-5 py-3.5 text-sm font-semibold"><span className={scoreColor(sub.score)}>{sub.score}/100</span></td>
                      <td className="px-5 py-3.5 text-sm text-slate-600">{sub.submittedBy}</td>
                      <td className="px-5 py-3.5 text-sm text-slate-500">{sub.submittedDate}</td>
                      <td className="px-5 py-3.5">
                        <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border ${statusStyle(sub.reviewStatus)}`}>
                          {sub.reviewStatus}
                        </span>
                      </td>
                      <td className="px-5 py-3.5">
                        <button onClick={() => { setThreatSelected(sub); setReviewNote(""); setConfirmAction(null); }}
                          className="text-[#1e3a5f] text-sm font-medium hover:underline">
                          Review
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}

      {/* ── Whitelist Requests Tab ── */}
      {activeTab === "whitelist" && (
        <div className="bg-white rounded-xl border border-slate-200 overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="text-xs text-slate-500 bg-slate-50 border-b border-slate-200">
                  {["URL", "Submitted By", "Date", "Risk Score", "Status", "Action"].map(h => (
                    <th key={h} className="text-left px-5 py-3 font-medium">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {wlItems.map(row => (
                  <tr key={row.id} className="hover:bg-slate-50 transition-colors">
                    <td className="px-5 py-3.5 text-sm font-mono text-slate-700">{row.url}</td>
                    <td className="px-5 py-3.5 text-sm text-slate-600">{row.by}</td>
                    <td className="px-5 py-3.5 text-sm text-slate-500">{row.date}</td>
                    <td className="px-5 py-3.5 text-sm font-semibold text-amber-600">{row.score}/100</td>
                    <td className="px-5 py-3.5"><StatusBadge status={row.status} /></td>
                    <td className="px-5 py-3.5">
                      <button onClick={() => setWlSelected(row)} className="text-[#1e3a5f] text-sm font-medium hover:underline">Review</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ── Threat Review Modal ── */}
      {threatSelected && (
        <div className="fixed inset-0 z-50 bg-black/40 flex items-center justify-center p-4">
          <div className="bg-white rounded-2xl shadow-xl w-full max-w-md max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between px-6 py-5 border-b border-slate-100">
              <div>
                <h3 className="font-semibold text-slate-900">Review Threat Submission</h3>
                <p className="text-slate-500 text-xs mt-0.5">Submitted by {threatSelected.submittedBy}</p>
              </div>
              <button onClick={() => setThreatSelected(null)} className="text-slate-400 hover:text-slate-600 text-2xl leading-none ml-4">×</button>
            </div>

            <div className="px-6 py-5 space-y-4">
              {/* Details */}
              <div className="divide-y divide-slate-100">
                {([
                  ["URL", <span className="font-mono text-xs text-slate-800 break-all">{threatSelected.url}</span>],
                  ["Category", <StatusBadge status={threatSelected.type} />],
                  ["Risk Score", <span className={`font-bold ${scoreColor(threatSelected.score)}`}>{threatSelected.score}/100</span>],
                  ["Risk bar", (
                    <div className="w-32 h-2 bg-slate-100 rounded-full overflow-hidden">
                      <div className={`h-full rounded-full ${threatSelected.score < 30 ? "bg-green-500" : threatSelected.score < 70 ? "bg-amber-500" : "bg-red-500"}`}
                        style={{ width: `${threatSelected.score}%` }} />
                    </div>
                  )],
                  ["Source", <span className="text-slate-700">{threatSelected.source}</span>],
                  ["Submitted", <span className="text-slate-700">{threatSelected.submittedDate}</span>],
                ] as [string, React.ReactNode][]).map(([l, v]) => (
                  <div key={l} className="flex items-center justify-between py-2.5 text-sm gap-4">
                    <span className="text-slate-500 shrink-0">{l}</span><div className="text-right">{v}</div>
                  </div>
                ))}
              </div>

              {/* Employer notes */}
              <div className="bg-slate-50 border border-slate-200 rounded-xl p-3.5">
                <p className="text-slate-500 text-xs mb-1.5 font-medium">Employer Notes</p>
                <p className="text-slate-700 text-sm leading-relaxed">{threatSelected.notes}</p>
              </div>

              {/* Review status */}
              {threatSelected.reviewStatus !== "Pending" && (
                <div className={`flex items-center gap-2 p-3 rounded-xl border text-sm font-medium ${statusStyle(threatSelected.reviewStatus)}`}>
                  <span>{threatSelected.reviewStatus === "Approved" ? "✓ Approved — Published to Global Threat List" : "✗ Rejected"}</span>
                </div>
              )}

              {/* Admin note textarea — only if pending */}
              {threatSelected.reviewStatus === "Pending" && (
                <div>
                  <label className="block text-sm font-medium text-slate-700 mb-1.5">Review Note <span className="text-slate-400 font-normal">(optional)</span></label>
                  <textarea value={reviewNote} onChange={e => setReviewNote(e.target.value)} rows={3}
                    placeholder="Add a note for the employer about your decision..."
                    className="w-full px-3.5 py-2.5 border border-slate-300 rounded-lg text-sm placeholder-slate-400 focus:outline-none focus:border-[#1e3a5f] focus:ring-2 focus:ring-[#1e3a5f]/10 resize-none" />
                </div>
              )}
            </div>

            <div className="px-6 py-4 border-t border-slate-100 flex gap-3">
              <button onClick={() => setThreatSelected(null)}
                className="flex-1 border border-slate-300 text-slate-700 py-2.5 rounded-lg text-sm font-medium hover:bg-slate-50">
                {threatSelected.reviewStatus === "Pending" ? "Cancel" : "Close"}
              </button>
              {threatSelected.reviewStatus === "Pending" && (
                <>
                  <button onClick={() => setConfirmAction("reject")}
                    className="flex-1 border border-red-300 text-red-600 py-2.5 rounded-lg text-sm font-semibold hover:bg-red-50 transition-colors">
                    Reject
                  </button>
                  <button onClick={() => setConfirmAction("approve")}
                    className="flex-1 bg-green-600 text-white py-2.5 rounded-lg text-sm font-semibold hover:bg-green-700 transition-colors">
                    Approve & Publish
                  </button>
                </>
              )}
            </div>
          </div>
        </div>
      )}

      {/* ── Confirm Action Modal ── */}
      {confirmAction && threatSelected && (
        <div className="fixed inset-0 z-[60] bg-black/50 flex items-center justify-center p-4">
          <div className="bg-white rounded-2xl p-6 max-w-sm w-full shadow-xl">
            <div className={`w-12 h-12 rounded-xl flex items-center justify-center mx-auto mb-4 text-xl ${confirmAction === "approve" ? "bg-green-100" : "bg-red-100"}`}>
              {confirmAction === "approve" ? "✓" : "✗"}
            </div>
            <h3 className="font-semibold text-slate-900 text-center mb-1">
              {confirmAction === "approve" ? "Approve & Publish?" : "Reject Submission?"}
            </h3>
            <p className="text-slate-500 text-sm text-center mb-1 font-mono">{threatSelected.url}</p>
            <p className="text-slate-500 text-sm text-center mb-5">
              {confirmAction === "approve"
                ? "This URL will be immediately published to the Global Threat List, visible to all users."
                : "The submission will be rejected and the employer will be notified."}
            </p>
            <div className="flex gap-3">
              <button onClick={() => setConfirmAction(null)}
                className="flex-1 border border-slate-300 text-slate-700 py-2.5 rounded-lg text-sm font-medium hover:bg-slate-50">Cancel</button>
              <button onClick={() => handleThreat(confirmAction)}
                className={`flex-1 py-2.5 rounded-lg text-sm font-semibold text-white transition-colors ${confirmAction === "approve" ? "bg-green-600 hover:bg-green-700" : "bg-red-600 hover:bg-red-700"}`}>
                Confirm
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── Whitelist Review Modal ── */}
      {wlSelected && (
        <div className="fixed inset-0 z-50 bg-black/40 flex items-center justify-center p-4">
          <div className="bg-white rounded-2xl p-6 max-w-md w-full shadow-xl space-y-4">
            <h3 className="font-semibold text-slate-900 text-lg">Whitelist Request Review</h3>
            <div className="divide-y divide-slate-100 text-sm">
              {[["URL", wlSelected.url], ["Submitted By", wlSelected.by], ["Risk Score", `${wlSelected.score}/100`], ["Reason", wlSelected.reason]].map(([l, v]) => (
                <div key={l} className="flex justify-between py-2.5">
                  <span className="text-slate-500">{l}</span>
                  <span className="text-slate-800 font-medium font-mono">{v}</span>
                </div>
              ))}
            </div>
            {wlSelected.status === "Pending" && (
              <div className="flex gap-3 pt-1">
                <button onClick={() => setWlSelected(null)} className="flex-1 border border-slate-300 text-slate-700 py-2.5 rounded-lg text-sm font-medium hover:bg-slate-50">Cancel</button>
                <button onClick={() => setWlConfirm({ action: "reject", id: wlSelected.id })} className="flex-1 border border-red-300 text-red-600 py-2.5 rounded-lg text-sm font-medium hover:bg-red-50">Reject</button>
                <button onClick={() => setWlConfirm({ action: "approve", id: wlSelected.id })} className="flex-1 bg-green-600 text-white py-2.5 rounded-lg text-sm font-semibold hover:bg-green-700">Approve</button>
              </div>
            )}
            {wlSelected.status !== "Pending" && (
              <button onClick={() => setWlSelected(null)} className="w-full border border-slate-300 text-slate-700 py-2.5 rounded-lg text-sm font-medium hover:bg-slate-50">Close</button>
            )}
          </div>
        </div>
      )}

      {wlConfirm && (
        <div className="fixed inset-0 z-[60] bg-black/40 flex items-center justify-center p-4">
          <div className="bg-white rounded-2xl p-6 max-w-sm w-full shadow-xl">
            <h3 className="font-semibold text-slate-900 mb-2">Confirm {wlConfirm.action === "approve" ? "Approval" : "Rejection"}</h3>
            <p className="text-slate-500 text-sm mb-5">Are you sure you want to {wlConfirm.action} this whitelist request?</p>
            <div className="flex gap-3">
              <button onClick={() => setWlConfirm(null)} className="flex-1 border border-slate-300 text-slate-700 py-2.5 rounded-lg text-sm font-medium">Cancel</button>
              <button onClick={() => handleWl(wlConfirm.action, wlConfirm.id)}
                className={`flex-1 py-2.5 rounded-lg text-sm font-semibold text-white ${wlConfirm.action === "approve" ? "bg-green-600" : "bg-red-600"}`}>
                Confirm
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
