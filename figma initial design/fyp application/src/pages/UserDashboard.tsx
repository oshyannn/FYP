import { useState } from "react";
import type { Page } from "../types";
import StatusBadge from "../components/StatusBadge";

interface Props { navigate: (page: Page, url?: string, status?: string, score?: number) => void; }

const recentActivity = [
  { url: "google.com", status: "SAFE" as const, score: 3, type: "Automatic", time: "10:32 AM" },
  { url: "example-site.com", status: "SUSPICIOUS" as const, score: 62, type: "Manual", time: "9:45 AM" },
  { url: "fake-login.com", status: "MALICIOUS" as const, score: 96, type: "Automatic", time: "Yesterday" },
];

export default function UserDashboard({ navigate }: Props) {
  const [url, setUrl] = useState("");

  const stats = [
    { label: "Total Scanned", value: 148, icon: "🔍", color: "text-[#1e3a5f]", bg: "bg-blue-50" },
    { label: "Safe URLs", value: 112, icon: "✓", color: "text-green-600", bg: "bg-green-50" },
    { label: "Suspicious", value: 23, icon: "⚠", color: "text-amber-600", bg: "bg-amber-50" },
    { label: "Malicious", value: 13, icon: "✗", color: "text-red-600", bg: "bg-red-50" },
  ];

  const scoreColor = (s: number) => s < 30 ? "text-green-600" : s < 70 ? "text-amber-600" : "text-red-600";

  return (
    <div className="space-y-6 max-w-6xl">
      {/* Welcome */}
      <div>
        <h2 className="text-xl font-bold text-slate-900">Welcome back, John!</h2>
        <p className="text-slate-500 text-sm mt-0.5">SafeBrowse is protecting your browsing activity.</p>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {stats.map(s => (
          <div key={s.label} className="bg-white rounded-xl border border-slate-200 p-5">
            <div className={`w-9 h-9 ${s.bg} rounded-lg flex items-center justify-center text-base mb-3 ${s.color}`}>
              {s.icon}
            </div>
            <div className={`text-2xl font-bold ${s.color}`}>{s.value}</div>
            <div className="text-slate-500 text-xs mt-1">{s.label}</div>
          </div>
        ))}
      </div>

      {/* Quick Scan */}
      <div className="bg-white rounded-xl border border-slate-200 p-6">
        <h3 className="font-semibold text-slate-800 mb-1">Quick URL Scan</h3>
        <p className="text-slate-500 text-sm mb-4">Check a website before visiting it.</p>
        <div className="flex gap-3">
          <input
            value={url}
            onChange={e => setUrl(e.target.value)}
            onKeyDown={e => e.key === "Enter" && url && navigate("scan-result", url || "https://example-site.com", "SUSPICIOUS", 62)}
            placeholder="Enter URL, e.g. https://example.com"
            className="flex-1 px-4 py-2.5 border border-slate-300 rounded-lg text-sm placeholder-slate-400 focus:outline-none focus:border-[#1e3a5f] focus:ring-2 focus:ring-[#1e3a5f]/10 transition-colors"
          />
          <button
            onClick={() => navigate("scan-result", url || "https://example-site.com", "SUSPICIOUS", 62)}
            className="bg-[#1e3a5f] text-white px-5 py-2.5 rounded-lg text-sm font-semibold hover:bg-[#162d4a] transition-colors whitespace-nowrap"
          >
            Scan URL
          </button>
        </div>
      </div>

      {/* Recent Activity */}
      <div className="bg-white rounded-xl border border-slate-200">
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-100">
          <h3 className="font-semibold text-slate-800">Recent Detection Activity</h3>
          <button onClick={() => navigate("detection-history")} className="text-sm text-[#1e3a5f] hover:underline font-medium">View All</button>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="text-xs text-slate-500 bg-slate-50">
                <th className="text-left px-6 py-3 font-medium">URL</th>
                <th className="text-left px-6 py-3 font-medium">Status</th>
                <th className="text-left px-6 py-3 font-medium">Risk Score</th>
                <th className="text-left px-6 py-3 font-medium">Detection Type</th>
                <th className="text-left px-6 py-3 font-medium">Time</th>
                <th className="text-left px-6 py-3 font-medium">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {recentActivity.map((row, i) => (
                <tr key={i} className="hover:bg-slate-50 transition-colors">
                  <td className="px-6 py-3.5 text-sm text-slate-700 font-mono">{row.url}</td>
                  <td className="px-6 py-3.5"><StatusBadge status={row.status} /></td>
                  <td className="px-6 py-3.5 text-sm font-semibold">
                    <span className={scoreColor(row.score)}>{row.score}/100</span>
                  </td>
                  <td className="px-6 py-3.5 text-sm text-slate-600">{row.type}</td>
                  <td className="px-6 py-3.5 text-sm text-slate-500">{row.time}</td>
                  <td className="px-6 py-3.5">
                    <button
                      onClick={() => navigate("detailed-analysis", row.url, row.status, row.score)}
                      className="text-[#1e3a5f] text-sm font-medium hover:underline"
                    >
                      View
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
