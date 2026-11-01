import type { Page } from "../types";
import StatusBadge from "../components/StatusBadge";

interface Props { navigate: (page: Page) => void; }

const recent = [
  { url: "example-site.com", risk: "SUSPICIOUS", by: "user@email.com", date: "31 Aug 2026" },
  { url: "fake-login.net", risk: "MALICIOUS", by: "john@email.com", date: "31 Aug 2026" },
  { url: "safe-portal.com", risk: "SAFE", by: "sarah@email.com", date: "30 Aug 2026" },
];

export default function EmployerDashboard({ navigate }: Props) {
  const stats = [
    { label: "Total Scanned URLs", value: 1248, color: "text-[#1e3a5f]", bg: "bg-blue-50", icon: "🔍" },
    { label: "Threat URLs", value: 86, color: "text-red-600", bg: "bg-red-50", icon: "⚠" },
    { label: "Pending Approvals", value: 12, color: "text-amber-600", bg: "bg-amber-50", icon: "⏳" },
    { label: "User Feedback", value: 34, color: "text-purple-600", bg: "bg-purple-50", icon: "✉" },
  ];

  return (
    <div className="max-w-5xl space-y-6">
      <div>
        <h2 className="text-xl font-bold text-slate-900">Employer Dashboard</h2>
        <p className="text-slate-500 text-sm mt-0.5">Monitor URL security activity and manage approvals.</p>
      </div>

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {stats.map(s => (
          <div key={s.label} className="bg-white rounded-xl border border-slate-200 p-5">
            <div className={`w-9 h-9 ${s.bg} rounded-lg flex items-center justify-center text-base mb-3 ${s.color}`}>{s.icon}</div>
            <div className={`text-2xl font-bold ${s.color}`}>{s.value}</div>
            <div className="text-slate-500 text-xs mt-1">{s.label}</div>
          </div>
        ))}
      </div>

      <div className="bg-white rounded-xl border border-slate-200">
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-100">
          <h3 className="font-semibold text-slate-800">Recent Security Activity</h3>
          <button onClick={() => navigate("url-approval")} className="text-sm text-[#1e3a5f] hover:underline font-medium">View All</button>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="text-xs text-slate-500 bg-slate-50">
                {["URL", "Risk Level", "Submitted By", "Date", "Action"].map(h => (
                  <th key={h} className="text-left px-5 py-3 font-medium">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {recent.map((row, i) => (
                <tr key={i} className="hover:bg-slate-50 transition-colors">
                  <td className="px-5 py-3.5 text-sm font-mono text-slate-700">{row.url}</td>
                  <td className="px-5 py-3.5"><StatusBadge status={row.risk} /></td>
                  <td className="px-5 py-3.5 text-sm text-slate-600">{row.by}</td>
                  <td className="px-5 py-3.5 text-sm text-slate-500">{row.date}</td>
                  <td className="px-5 py-3.5">
                    <button onClick={() => navigate("url-approval")} className="text-[#1e3a5f] text-sm font-medium hover:underline">Review</button>
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
