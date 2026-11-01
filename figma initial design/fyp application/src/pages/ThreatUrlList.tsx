import { useState } from "react";
import StatusBadge from "../components/StatusBadge";
import type { Role } from "../types";
import type { ThreatEntry, PendingSubmission } from "../threatStore";

const emptyForm = { url: "", type: "Phishing", score: "", source: "Employer Report", notes: "" };

interface Props {
  role?: Role | null;
  threats: ThreatEntry[];
  mySubmissions?: PendingSubmission[];
  onSubmit?: (entry: Omit<ThreatEntry, "id" | "date" | "status">) => void;
}

export default function ThreatUrlList({ role, threats, mySubmissions = [], onSubmit }: Props) {
  const [search, setSearch] = useState("");
  const [filterType, setFilterType] = useState("all");
  const [showAdd, setShowAdd] = useState(false);
  const [viewItem, setViewItem] = useState<ThreatEntry | null>(null);
  const [viewSub, setViewSub] = useState<PendingSubmission | null>(null);
  const [activeTab, setActiveTab] = useState<"global" | "my">("global");
  const [form, setForm] = useState(emptyForm);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [successMsg, setSuccessMsg] = useState("");

  const canSubmit = role === "employer";

  const stats = [
    { label: "Total Threats", value: threats.length, color: "text-slate-800", bg: "bg-slate-50" },
    { label: "Phishing", value: threats.filter(t => t.type === "Phishing").length, color: "text-orange-600", bg: "bg-orange-50" },
    { label: "Malware", value: threats.filter(t => t.type === "Malware").length, color: "text-red-600", bg: "bg-red-50" },
    { label: "Suspicious", value: threats.filter(t => t.type === "Suspicious").length, color: "text-amber-600", bg: "bg-amber-50" },
  ];

  const filtered = threats.filter(t =>
    t.url.toLowerCase().includes(search.toLowerCase()) &&
    (filterType === "all" || t.type.toLowerCase() === filterType.toLowerCase())
  );

  const setField = (k: string, v: string) => {
    setForm(f => ({ ...f, [k]: v }));
    setErrors(e => ({ ...e, [k]: "" }));
  };

  const validate = () => {
    const e: Record<string, string> = {};
    if (!form.url.trim()) e.url = "URL is required.";
    if (!form.score || isNaN(Number(form.score)) || Number(form.score) < 0 || Number(form.score) > 100)
      e.score = "Enter a risk score between 0 and 100.";
    if (!form.notes.trim()) e.notes = "Notes / reason is required.";
    setErrors(e);
    return Object.keys(e).length === 0;
  };

  const handleSubmit = () => {
    if (!validate() || !onSubmit) return;
    onSubmit({
      url: form.url.trim().replace(/^https?:\/\//, ""),
      type: form.type,
      score: Number(form.score),
      source: form.source,
      notes: form.notes.trim(),
    });
    setForm(emptyForm);
    setShowAdd(false);
    setSuccessMsg("Your submission has been sent to the Admin Approval Queue.");
    setActiveTab("my");
    setTimeout(() => setSuccessMsg(""), 5000);
  };

  const scoreColor = (s: number) => s < 30 ? "text-green-600" : s < 70 ? "text-amber-600" : "text-red-600";

  const subStatusColor = (s: string) =>
    s === "Approved" ? "bg-green-50 text-green-700 border-green-200"
    : s === "Rejected" ? "bg-red-50 text-red-700 border-red-200"
    : "bg-amber-50 text-amber-700 border-amber-200";

  return (
    <div className="max-w-5xl space-y-5">
      {/* Header */}
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h2 className="text-xl font-bold text-slate-900">Threat URL List</h2>
          <p className="text-slate-500 text-sm mt-0.5">Global list of malicious or suspicious URLs detected by SafeBrowse.</p>
        </div>
        {canSubmit && (
          <button
            onClick={() => { setShowAdd(true); setForm(emptyForm); setErrors({}); }}
            className="shrink-0 bg-[#1e3a5f] text-white px-4 py-2.5 rounded-lg text-sm font-semibold hover:bg-[#162d4a] transition-colors flex items-center gap-2"
          >
            <span className="text-base leading-none">+</span> Submit Threat URL
          </button>
        )}
      </div>

      {/* Success banner */}
      {successMsg && (
        <div className="flex items-center gap-3 px-4 py-3 bg-blue-50 border border-blue-200 rounded-xl text-blue-700 text-sm">
          <span className="text-lg">📋</span>
          <div>
            <p className="font-medium">{successMsg}</p>
            <p className="text-xs text-blue-600 mt-0.5">An admin will review your submission. You can track its status in <b>My Submissions</b>.</p>
          </div>
        </div>
      )}

      {/* Stats */}
      <div className="grid grid-cols-4 gap-4">
        {stats.map(s => (
          <div key={s.label} className={`${s.bg} rounded-xl border border-slate-200 p-4 text-center`}>
            <div className={`text-2xl font-bold ${s.color}`}>{s.value}</div>
            <div className="text-slate-500 text-xs mt-1">{s.label}</div>
          </div>
        ))}
      </div>

      {/* Tabs — employer sees My Submissions tab */}
      {canSubmit && (
        <div className="flex border-b border-slate-200">
          {[
            { key: "global", label: "Global Threat List" },
            { key: "my", label: `My Submissions`, badge: mySubmissions.filter(s => s.reviewStatus === "Pending").length },
          ].map(tab => (
            <button
              key={tab.key}
              onClick={() => setActiveTab(tab.key as "global" | "my")}
              className={`flex items-center gap-2 px-4 py-2.5 text-sm font-medium border-b-2 transition-colors ${
                activeTab === tab.key
                  ? "border-[#1e3a5f] text-[#1e3a5f]"
                  : "border-transparent text-slate-500 hover:text-slate-700"
              }`}
            >
              {tab.label}
              {tab.badge ? (
                <span className="bg-amber-500 text-white text-[10px] font-bold px-1.5 py-0.5 rounded-full">{tab.badge}</span>
              ) : null}
            </button>
          ))}
        </div>
      )}

      {/* ── Global Threat List ── */}
      {activeTab === "global" && (
        <>
          <div className="flex gap-3 flex-wrap">
            <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search threat URL..."
              className="flex-1 min-w-48 px-3.5 py-2 border border-slate-300 rounded-lg text-sm placeholder-slate-400 bg-white focus:outline-none focus:border-[#1e3a5f] focus:ring-2 focus:ring-[#1e3a5f]/10" />
            <select value={filterType} onChange={e => setFilterType(e.target.value)}
              className="px-3.5 py-2 border border-slate-300 rounded-lg text-sm bg-white text-slate-700 focus:outline-none focus:border-[#1e3a5f]">
              <option value="all">All Categories</option>
              <option value="phishing">Phishing</option>
              <option value="malware">Malware</option>
              <option value="suspicious">Suspicious</option>
            </select>
          </div>

          <div className="bg-white rounded-xl border border-slate-200 overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="text-xs text-slate-500 bg-slate-50 border-b border-slate-200">
                    {["URL", "Threat Type", "Risk Score", "Source", "Status", "Date", "Action"].map(h => (
                      <th key={h} className="text-left px-5 py-3 font-medium">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {filtered.map(row => (
                    <tr key={row.id} className="hover:bg-slate-50 transition-colors">
                      <td className="px-5 py-3.5 text-sm font-mono text-slate-700">{row.url}</td>
                      <td className="px-5 py-3.5"><StatusBadge status={row.type} /></td>
                      <td className="px-5 py-3.5 text-sm font-semibold"><span className={scoreColor(row.score)}>{row.score}/100</span></td>
                      <td className="px-5 py-3.5 text-sm text-slate-500">{row.source}</td>
                      <td className="px-5 py-3.5"><StatusBadge status={row.status} /></td>
                      <td className="px-5 py-3.5 text-sm text-slate-500">{row.date}</td>
                      <td className="px-5 py-3.5">
                        <button onClick={() => setViewItem(row)} className="text-[#1e3a5f] text-sm font-medium hover:underline">View</button>
                      </td>
                    </tr>
                  ))}
                  {filtered.length === 0 && (
                    <tr><td colSpan={7} className="px-5 py-10 text-center text-slate-400 text-sm">No threats found.</td></tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}

      {/* ── My Submissions (Employer only) ── */}
      {activeTab === "my" && (
        <div className="bg-white rounded-xl border border-slate-200 overflow-hidden">
          <div className="px-5 py-4 border-b border-slate-100 flex items-center justify-between">
            <div>
              <h3 className="font-semibold text-slate-800">My Submissions</h3>
              <p className="text-slate-500 text-xs mt-0.5">Track approval status of your submitted threat URLs.</p>
            </div>
          </div>
          {mySubmissions.length === 0 ? (
            <div className="px-5 py-12 text-center text-slate-400 text-sm">No submissions yet. Use <b>Submit Threat URL</b> to report a malicious site.</div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="text-xs text-slate-500 bg-slate-50 border-b border-slate-200">
                    {["URL", "Type", "Risk Score", "Submitted", "Review Status", "Action"].map(h => (
                      <th key={h} className="text-left px-5 py-3 font-medium">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {mySubmissions.map(sub => (
                    <tr key={sub.id} className="hover:bg-slate-50 transition-colors">
                      <td className="px-5 py-3.5 text-sm font-mono text-slate-700">{sub.url}</td>
                      <td className="px-5 py-3.5"><StatusBadge status={sub.type} /></td>
                      <td className="px-5 py-3.5 text-sm font-semibold"><span className={scoreColor(sub.score)}>{sub.score}/100</span></td>
                      <td className="px-5 py-3.5 text-sm text-slate-500">{sub.submittedDate}</td>
                      <td className="px-5 py-3.5">
                        <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border ${subStatusColor(sub.reviewStatus)}`}>
                          {sub.reviewStatus}
                        </span>
                      </td>
                      <td className="px-5 py-3.5">
                        <button onClick={() => setViewSub(sub)} className="text-[#1e3a5f] text-sm font-medium hover:underline">View</button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* ── Submit Modal ── */}
      {showAdd && (
        <div className="fixed inset-0 z-50 bg-black/40 flex items-center justify-center p-4">
          <div className="bg-white rounded-2xl shadow-xl w-full max-w-lg max-h-[90vh] overflow-y-auto">
            <div className="flex items-start justify-between px-6 py-5 border-b border-slate-100">
              <div>
                <h3 className="font-semibold text-slate-900 text-lg">Submit Threat URL</h3>
                <p className="text-slate-500 text-xs mt-0.5">Your submission will be sent to the Admin Approval Queue before being published.</p>
              </div>
              <button onClick={() => setShowAdd(false)} className="text-slate-400 hover:text-slate-600 text-2xl leading-none ml-4">×</button>
            </div>

            {/* Workflow hint */}
            <div className="mx-6 mt-5 flex items-center gap-0">
              {["You Submit", "Admin Reviews", "Published to All"].map((step, i) => (
                <div key={step} className="flex items-center flex-1">
                  <div className="flex flex-col items-center flex-1">
                    <div className={`w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold ${i === 0 ? "bg-[#1e3a5f] text-white" : "bg-slate-200 text-slate-500"}`}>{i + 1}</div>
                    <span className="text-[10px] text-slate-500 mt-1 text-center leading-tight">{step}</span>
                  </div>
                  {i < 2 && <div className="w-8 h-px bg-slate-300 shrink-0 mb-3" />}
                </div>
              ))}
            </div>

            <div className="px-6 py-5 space-y-4">
              <div>
                <label className="block text-sm font-medium text-slate-700 mb-1.5">Threat URL <span className="text-red-500">*</span></label>
                <input value={form.url} onChange={e => setField("url", e.target.value)}
                  placeholder="https://malicious-example.com"
                  className={`w-full px-3.5 py-2.5 border rounded-lg text-sm font-mono placeholder-slate-400 focus:outline-none focus:ring-2 transition-colors
                    ${errors.url ? "border-red-400 focus:border-red-400 focus:ring-red-100" : "border-slate-300 focus:border-[#1e3a5f] focus:ring-[#1e3a5f]/10"}`} />
                {errors.url && <p className="text-red-500 text-xs mt-1">{errors.url}</p>}
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-slate-700 mb-1.5">Threat Category <span className="text-red-500">*</span></label>
                  <select value={form.type} onChange={e => setField("type", e.target.value)}
                    className="w-full px-3.5 py-2.5 border border-slate-300 rounded-lg text-sm bg-white text-slate-700 focus:outline-none focus:border-[#1e3a5f]">
                    <option value="Phishing">Phishing</option>
                    <option value="Malware">Malware</option>
                    <option value="Suspicious">Suspicious</option>
                    <option value="Spam">Spam</option>
                    <option value="Scam">Scam</option>
                  </select>
                </div>
                <div>
                  <label className="block text-sm font-medium text-slate-700 mb-1.5">Risk Score (0–100) <span className="text-red-500">*</span></label>
                  <input type="number" min={0} max={100} value={form.score} onChange={e => setField("score", e.target.value)}
                    placeholder="e.g. 95"
                    className={`w-full px-3.5 py-2.5 border rounded-lg text-sm placeholder-slate-400 focus:outline-none focus:ring-2 transition-colors
                      ${errors.score ? "border-red-400 focus:border-red-400 focus:ring-red-100" : "border-slate-300 focus:border-[#1e3a5f] focus:ring-[#1e3a5f]/10"}`} />
                  {errors.score && <p className="text-red-500 text-xs mt-1">{errors.score}</p>}
                  {form.score !== "" && !isNaN(Number(form.score)) && (
                    <div className="mt-1.5 h-1.5 bg-slate-100 rounded-full overflow-hidden">
                      <div className={`h-full rounded-full ${Number(form.score) < 30 ? "bg-green-500" : Number(form.score) < 70 ? "bg-amber-500" : "bg-red-500"}`}
                        style={{ width: `${Math.min(100, Math.max(0, Number(form.score)))}%` }} />
                    </div>
                  )}
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium text-slate-700 mb-1.5">Notes / Reason <span className="text-red-500">*</span></label>
                <textarea value={form.notes} onChange={e => setField("notes", e.target.value)} rows={3}
                  placeholder="Describe why this URL is a threat. The more detail you provide, the faster admin can review it."
                  className={`w-full px-3.5 py-2.5 border rounded-lg text-sm placeholder-slate-400 focus:outline-none focus:ring-2 resize-none transition-colors
                    ${errors.notes ? "border-red-400 focus:border-red-400 focus:ring-red-100" : "border-slate-300 focus:border-[#1e3a5f] focus:ring-[#1e3a5f]/10"}`} />
                {errors.notes && <p className="text-red-500 text-xs mt-1">{errors.notes}</p>}
              </div>
            </div>

            <div className="px-6 py-4 border-t border-slate-100 flex gap-3">
              <button onClick={() => setShowAdd(false)}
                className="flex-1 border border-slate-300 text-slate-700 py-2.5 rounded-lg text-sm font-medium hover:bg-slate-50">Cancel</button>
              <button onClick={handleSubmit}
                className="flex-1 bg-[#1e3a5f] text-white py-2.5 rounded-lg text-sm font-semibold hover:bg-[#162d4a]">
                Submit for Review
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── View Threat Detail ── */}
      {viewItem && (
        <div className="fixed inset-0 z-50 bg-black/40 flex items-center justify-center p-4">
          <div className="bg-white rounded-2xl shadow-xl w-full max-w-md">
            <div className="flex items-center justify-between px-6 py-5 border-b border-slate-100">
              <h3 className="font-semibold text-slate-900">Threat URL Details</h3>
              <button onClick={() => setViewItem(null)} className="text-slate-400 hover:text-slate-600 text-2xl leading-none">×</button>
            </div>
            <div className="px-6 py-5 divide-y divide-slate-100">
              {([["URL", <span className="font-mono text-slate-800 text-xs break-all">{viewItem.url}</span>],
                ["Threat Type", <StatusBadge status={viewItem.type} />],
                ["Risk Score", <span className={`font-bold ${scoreColor(viewItem.score)}`}>{viewItem.score}/100</span>],
                ["Status", <StatusBadge status={viewItem.status} />],
                ["Source", <span className="text-slate-700">{viewItem.source}</span>],
                ["Detected", <span className="text-slate-700">{viewItem.date}</span>],
              ] as [string, React.ReactNode][]).map(([label, value]) => (
                <div key={label} className="flex items-center justify-between py-3 text-sm gap-4">
                  <span className="text-slate-500 shrink-0">{label}</span>
                  <div className="text-right">{value}</div>
                </div>
              ))}
              <div className="py-3">
                <p className="text-slate-500 text-sm mb-1.5">Notes</p>
                <p className="text-slate-700 text-sm leading-relaxed">{viewItem.notes}</p>
              </div>
            </div>
            <div className="px-6 py-4 border-t border-slate-100">
              <button onClick={() => setViewItem(null)}
                className="w-full border border-slate-300 text-slate-700 py-2.5 rounded-lg text-sm font-medium hover:bg-slate-50">Close</button>
            </div>
          </div>
        </div>
      )}

      {/* ── View Submission Status ── */}
      {viewSub && (
        <div className="fixed inset-0 z-50 bg-black/40 flex items-center justify-center p-4">
          <div className="bg-white rounded-2xl shadow-xl w-full max-w-md">
            <div className="flex items-center justify-between px-6 py-5 border-b border-slate-100">
              <h3 className="font-semibold text-slate-900">Submission Details</h3>
              <button onClick={() => setViewSub(null)} className="text-slate-400 hover:text-slate-600 text-2xl leading-none">×</button>
            </div>
            <div className="px-6 py-5 space-y-4">
              <div className={`flex items-center gap-3 p-3.5 rounded-xl border ${subStatusColor(viewSub.reviewStatus)}`}>
                <span className="text-lg">{viewSub.reviewStatus === "Approved" ? "✓" : viewSub.reviewStatus === "Rejected" ? "✗" : "⏳"}</span>
                <div>
                  <p className="text-sm font-semibold">{viewSub.reviewStatus === "Pending" ? "Awaiting Admin Review" : viewSub.reviewStatus === "Approved" ? "Approved — Published to Global List" : "Rejected by Admin"}</p>
                  <p className="text-xs mt-0.5 opacity-80">Submitted on {viewSub.submittedDate}</p>
                </div>
              </div>
              <div className="divide-y divide-slate-100">
                {([["URL", <span className="font-mono text-xs">{viewSub.url}</span>],
                  ["Category", <StatusBadge status={viewSub.type} />],
                  ["Risk Score", <span className={`font-bold ${scoreColor(viewSub.score)}`}>{viewSub.score}/100</span>],
                ] as [string, React.ReactNode][]).map(([l, v]) => (
                  <div key={l} className="flex items-center justify-between py-2.5 text-sm gap-4">
                    <span className="text-slate-500">{l}</span><div>{v}</div>
                  </div>
                ))}
              </div>
              <div>
                <p className="text-slate-500 text-xs mb-1">Your Notes</p>
                <p className="text-slate-700 text-sm leading-relaxed">{viewSub.notes}</p>
              </div>
              {viewSub.reviewNote && (
                <div className="bg-slate-50 border border-slate-200 rounded-xl p-3.5">
                  <p className="text-slate-500 text-xs mb-1">Admin Response</p>
                  <p className="text-slate-700 text-sm leading-relaxed">{viewSub.reviewNote}</p>
                </div>
              )}
            </div>
            <div className="px-6 py-4 border-t border-slate-100">
              <button onClick={() => setViewSub(null)}
                className="w-full border border-slate-300 text-slate-700 py-2.5 rounded-lg text-sm font-medium hover:bg-slate-50">Close</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
