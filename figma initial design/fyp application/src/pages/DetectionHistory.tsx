import { useState } from "react";
import type { Page } from "../types";
import StatusBadge from "../components/StatusBadge";

interface Props { navigate: (page: Page, url?: string, status?: string, score?: number) => void; }

const allRecords = [
  { url: "example.com", status: "SAFE" as const, score: 4, type: "Automatic", date: "31 Aug 2026 10:32" },
  { url: "shopping-example.com", status: "SUSPICIOUS" as const, score: 65, type: "Manual", date: "30 Aug 2026 15:20" },
  { url: "fake-login.com", status: "MALICIOUS" as const, score: 95, type: "Automatic", date: "30 Aug 2026 12:15" },
  { url: "google.com", status: "SAFE" as const, score: 2, type: "Automatic", date: "29 Aug 2026 09:05" },
  { url: "phishing-site.net", status: "MALICIOUS" as const, score: 98, type: "Automatic", date: "29 Aug 2026 08:44" },
  { url: "news-portal.com", status: "SAFE" as const, score: 8, type: "Automatic", date: "28 Aug 2026 14:10" },
  { url: "free-prizes.xyz", status: "SUSPICIOUS" as const, score: 71, type: "Manual", date: "28 Aug 2026 11:30" },
];

export default function DetectionHistory({ navigate }: Props) {
  const [search, setSearch] = useState("");
  const [filterStatus, setFilterStatus] = useState("all");
  const [filterType, setFilterType] = useState("all");
  const [records, setRecords] = useState(allRecords);
  const [deleteTarget, setDeleteTarget] = useState<number | null>(null);
  const [page, setPage] = useState(1);
  const perPage = 5;

  const filtered = records.filter(r =>
    r.url.toLowerCase().includes(search.toLowerCase()) &&
    (filterStatus === "all" || r.status.toLowerCase() === filterStatus) &&
    (filterType === "all" || r.type.toLowerCase() === filterType)
  );

  const pages = Math.ceil(filtered.length / perPage);
  const paged = filtered.slice((page - 1) * perPage, page * perPage);

  const scoreColor = (s: number) => s < 30 ? "text-green-600" : s < 70 ? "text-amber-600" : "text-red-600";

  return (
    <div className="max-w-6xl space-y-5">
      <div>
        <h2 className="text-xl font-bold text-slate-900">Detection History</h2>
        <p className="text-slate-500 text-sm mt-0.5">View and manage your previously scanned URLs.</p>
      </div>

      {/* Filters */}
      <div className="bg-white rounded-xl border border-slate-200 p-4 flex flex-wrap gap-3">
        <input
          value={search}
          onChange={e => { setSearch(e.target.value); setPage(1); }}
          placeholder="Search URL..."
          className="flex-1 min-w-36 px-3.5 py-2 border border-slate-300 rounded-lg text-sm placeholder-slate-400 focus:outline-none focus:border-[#1e3a5f] focus:ring-2 focus:ring-[#1e3a5f]/10 transition-colors"
        />
        <select value={filterStatus} onChange={e => { setFilterStatus(e.target.value); setPage(1); }}
          className="px-3.5 py-2 border border-slate-300 rounded-lg text-sm bg-white text-slate-700 focus:outline-none focus:border-[#1e3a5f]">
          <option value="all">All Status</option>
          <option value="safe">Safe</option>
          <option value="suspicious">Suspicious</option>
          <option value="malicious">Malicious</option>
        </select>
        <select value={filterType} onChange={e => { setFilterType(e.target.value); setPage(1); }}
          className="px-3.5 py-2 border border-slate-300 rounded-lg text-sm bg-white text-slate-700 focus:outline-none focus:border-[#1e3a5f]">
          <option value="all">All Types</option>
          <option value="automatic">Automatic</option>
          <option value="manual">Manual</option>
        </select>
        <button onClick={() => { setSearch(""); setFilterStatus("all"); setFilterType("all"); setPage(1); }}
          className="px-3.5 py-2 border border-slate-300 rounded-lg text-sm text-slate-600 hover:bg-slate-50 transition-colors">
          Clear Filters
        </button>
      </div>

      {/* Table */}
      <div className="bg-white rounded-xl border border-slate-200 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="text-xs text-slate-500 bg-slate-50 border-b border-slate-200">
                {["URL", "Status", "Risk Score", "Scan Type", "Date & Time", "Action"].map(h => (
                  <th key={h} className="text-left px-5 py-3 font-medium">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {paged.map((row, i) => (
                <tr key={i} className="hover:bg-slate-50 transition-colors">
                  <td className="px-5 py-3.5 text-sm font-mono text-slate-700">{row.url}</td>
                  <td className="px-5 py-3.5"><StatusBadge status={row.status} /></td>
                  <td className="px-5 py-3.5 text-sm font-semibold"><span className={scoreColor(row.score)}>{row.score}/100</span></td>
                  <td className="px-5 py-3.5 text-sm text-slate-600">{row.type}</td>
                  <td className="px-5 py-3.5 text-sm text-slate-500">{row.date}</td>
                  <td className="px-5 py-3.5">
                    <div className="flex items-center gap-3">
                      <button onClick={() => navigate("detailed-analysis", row.url, row.status, row.score)}
                        className="text-[#1e3a5f] text-sm font-medium hover:underline">View</button>
                      <button onClick={() => setDeleteTarget(records.indexOf(row))}
                        className="text-red-500 text-sm font-medium hover:underline">Delete</button>
                    </div>
                  </td>
                </tr>
              ))}
              {paged.length === 0 && (
                <tr><td colSpan={6} className="px-5 py-10 text-center text-slate-400 text-sm">No records found.</td></tr>
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        {pages > 1 && (
          <div className="px-5 py-3.5 border-t border-slate-100 flex items-center justify-between text-sm text-slate-600">
            <span>Showing {(page - 1) * perPage + 1}–{Math.min(page * perPage, filtered.length)} of {filtered.length}</span>
            <div className="flex gap-1">
              {Array.from({ length: pages }, (_, i) => i + 1).map(p => (
                <button key={p} onClick={() => setPage(p)}
                  className={`w-8 h-8 rounded-lg text-sm font-medium transition-colors ${p === page ? "bg-[#1e3a5f] text-white" : "hover:bg-slate-100 text-slate-600"}`}>
                  {p}
                </button>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Delete modal */}
      {deleteTarget !== null && (
        <div className="fixed inset-0 z-50 bg-black/40 flex items-center justify-center p-4">
          <div className="bg-white rounded-2xl p-6 max-w-sm w-full shadow-xl">
            <h3 className="font-semibold text-slate-900 mb-2">Delete Detection Record?</h3>
            <p className="text-slate-500 text-sm mb-5">This action cannot be undone.</p>
            <div className="flex gap-3">
              <button onClick={() => setDeleteTarget(null)}
                className="flex-1 border border-slate-300 text-slate-700 py-2.5 rounded-lg text-sm font-medium hover:bg-slate-50">Cancel</button>
              <button onClick={() => {
                setRecords(r => r.filter((_, i) => i !== deleteTarget));
                setDeleteTarget(null);
              }}
                className="flex-1 bg-red-600 text-white py-2.5 rounded-lg text-sm font-medium hover:bg-red-700">Delete</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
