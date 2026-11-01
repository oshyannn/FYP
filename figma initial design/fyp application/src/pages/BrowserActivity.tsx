import type { Page } from "../types";
import StatusBadge from "../components/StatusBadge";

interface Props { navigate: (page: Page, url?: string, status?: string, score?: number) => void; }

const activity = [
  { time: "10:32 AM", url: "google.com", status: "SAFE" as const, score: 3 },
  { time: "10:33 AM", url: "news-site.com", status: "SAFE" as const, score: 8 },
  { time: "10:35 AM", url: "suspicious-site.com", status: "SUSPICIOUS" as const, score: 67 },
  { time: "10:38 AM", url: "youtube.com", status: "SAFE" as const, score: 2 },
  { time: "10:42 AM", url: "fake-banking.net", status: "MALICIOUS" as const, score: 94 },
  { time: "10:45 AM", url: "github.com", status: "SAFE" as const, score: 1 },
];

const scoreColor = (s: number) => s < 30 ? "text-green-600" : s < 70 ? "text-amber-600" : "text-red-600";

export default function BrowserActivity({ navigate }: Props) {
  return (
    <div className="max-w-4xl space-y-5">
      <div className="flex items-start justify-between">
        <div>
          <h2 className="text-xl font-bold text-slate-900">Browser Activity</h2>
          <p className="text-slate-500 text-sm mt-0.5">URLs captured by the SafeBrowse Chrome Extension in real time.</p>
        </div>
        <div className="flex items-center gap-2 bg-green-50 border border-green-200 px-3 py-1.5 rounded-full">
          <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse" />
          <span className="text-green-700 text-xs font-medium">Extension Connected</span>
        </div>
      </div>

      {/* Live label */}
      <div className="flex items-center gap-2">
        <div className="w-2 h-2 bg-red-500 rounded-full animate-pulse" />
        <span className="text-red-600 text-xs font-semibold tracking-wide">LIVE EXTENSION ACTIVITY</span>
      </div>

      {/* Table */}
      <div className="bg-white rounded-xl border border-slate-200 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="text-xs text-slate-500 bg-slate-50 border-b border-slate-200">
                {["Time", "Current URL", "Status", "Risk Score", "Action"].map(h => (
                  <th key={h} className="text-left px-5 py-3 font-medium">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {activity.map((row, i) => (
                <tr key={i} className="hover:bg-slate-50 transition-colors">
                  <td className="px-5 py-3.5 text-sm text-slate-500 font-mono">{row.time}</td>
                  <td className="px-5 py-3.5 text-sm text-slate-700 font-mono">{row.url}</td>
                  <td className="px-5 py-3.5"><StatusBadge status={row.status} /></td>
                  <td className="px-5 py-3.5 text-sm font-semibold"><span className={scoreColor(row.score)}>{row.score}/100</span></td>
                  <td className="px-5 py-3.5">
                    <button
                      onClick={() => navigate("detailed-analysis", row.url, row.status, row.score)}
                      className="text-[#1e3a5f] text-sm font-medium hover:underline"
                    >
                      View Details in SafeBrowse
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Info card */}
      <div className="bg-blue-50 border border-blue-200 rounded-xl p-4 flex gap-3">
        <div className="text-blue-500 text-xl shrink-0">ℹ</div>
        <div>
          <p className="text-blue-800 text-sm font-medium">Chrome Extension Active</p>
          <p className="text-blue-600 text-xs mt-0.5">The SafeBrowse extension is automatically scanning all URLs you visit and sending results to this dashboard in real time.</p>
        </div>
      </div>
    </div>
  );
}
