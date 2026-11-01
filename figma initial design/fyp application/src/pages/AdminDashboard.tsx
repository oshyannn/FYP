import type { Page } from "../types";
import StatusBadge from "../components/StatusBadge";

interface Props { navigate: (page: Page) => void; pendingCount?: number; }

const recentActivity = [
  { admin: "Admin", action: "Approved URL", target: "example.com", time: "31 Aug 10:30", status: "Successful" },
  { admin: "Admin", action: "Deactivated User", target: "user@email.com", time: "31 Aug 09:20", status: "Successful" },
  { admin: "Admin", action: "Verified Employer", target: "sarah@corp.com", time: "30 Aug 14:05", status: "Successful" },
];

const barData = [
  { label: "Safe", value: 72, color: "bg-green-500" },
  { label: "Suspicious", value: 18, color: "bg-amber-500" },
  { label: "Malicious", value: 10, color: "bg-red-500" },
];

export default function AdminDashboard({ navigate, pendingCount = 0 }: Props) {
  const stats = [
    { label: "Total Users", value: 248, color: "text-[#1e3a5f]", bg: "bg-blue-50", icon: "👤" },
    { label: "Total Employers", value: 34, color: "text-purple-600", bg: "bg-purple-50", icon: "🏢" },
    { label: "Pending Verification", value: 7, color: "text-amber-600", bg: "bg-amber-50", icon: "⏳" },
    { label: "Threat URLs", value: 86, color: "text-red-600", bg: "bg-red-50", icon: "⚠" },
  ];

  return (
    <div className="max-w-5xl space-y-6">
      <div>
        <h2 className="text-xl font-bold text-slate-900">Admin Dashboard</h2>
        <p className="text-slate-500 text-sm mt-0.5">System-wide security overview and management.</p>
      </div>

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {stats.map(s => (
          <div key={s.label} className="bg-white rounded-xl border border-slate-200 p-5">
            <div className={`w-9 h-9 ${s.bg} rounded-lg flex items-center justify-center text-base mb-3`}>{s.icon}</div>
            <div className={`text-2xl font-bold ${s.color}`}>{s.value}</div>
            <div className="text-slate-500 text-xs mt-1">{s.label}</div>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {/* Chart */}
        <div className="bg-white rounded-xl border border-slate-200 p-5">
          <h3 className="font-semibold text-slate-800 mb-4">System Security Overview</h3>
          <div className="space-y-3">
            {barData.map(b => (
              <div key={b.label}>
                <div className="flex justify-between text-sm mb-1.5">
                  <span className="text-slate-600">{b.label} URLs</span>
                  <span className="text-slate-800 font-medium">{b.value}%</span>
                </div>
                <div className="h-2.5 bg-slate-100 rounded-full overflow-hidden">
                  <div className={`h-full ${b.color} rounded-full`} style={{ width: `${b.value}%` }} />
                </div>
              </div>
            ))}
          </div>
          <div className="mt-4 pt-4 border-t border-slate-100 flex gap-4 text-xs text-slate-500">
            {barData.map(b => (
              <div key={b.label} className="flex items-center gap-1.5">
                <div className={`w-2.5 h-2.5 rounded-full ${b.color}`} />
                {b.label}
              </div>
            ))}
          </div>
        </div>

        {/* Quick links */}
        <div className="bg-white rounded-xl border border-slate-200 p-5">
          <h3 className="font-semibold text-slate-800 mb-4">Quick Access</h3>
          <div className="grid grid-cols-2 gap-3">
            {[
              { label: "User Management", page: "user-management" as Page, icon: "👤", badge: "248" },
              { label: "Employer Verification", page: "employer-verification" as Page, icon: "✓", badge: "7 pending" },
              { label: "URL Approval", page: "admin-url-approval" as Page, icon: "⌕", badge: pendingCount > 0 ? `${pendingCount} pending` : "" },
              { label: "Activity Logs", page: "activity-logs" as Page, icon: "📋", badge: "" },
            ].map(item => (
              <button key={item.label} onClick={() => navigate(item.page)}
                className="flex flex-col items-start gap-1 p-3.5 border border-slate-200 rounded-xl hover:bg-slate-50 hover:border-[#1e3a5f]/30 transition-colors text-left">
                <span className="text-xl">{item.icon}</span>
                <span className="text-xs font-medium text-slate-700">{item.label}</span>
                {item.badge && <span className="text-xs text-[#1e3a5f] font-semibold">{item.badge}</span>}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Activity */}
      <div className="bg-white rounded-xl border border-slate-200">
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-100">
          <h3 className="font-semibold text-slate-800">Recent Admin Activity</h3>
          <button onClick={() => navigate("activity-logs")} className="text-sm text-[#1e3a5f] hover:underline font-medium">View All</button>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="text-xs text-slate-500 bg-slate-50">
                {["Admin", "Action", "Target", "Date/Time", "Status"].map(h => (
                  <th key={h} className="text-left px-5 py-3 font-medium">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {recentActivity.map((row, i) => (
                <tr key={i} className="hover:bg-slate-50 transition-colors">
                  <td className="px-5 py-3.5 text-sm font-medium text-slate-700">{row.admin}</td>
                  <td className="px-5 py-3.5 text-sm text-slate-600">{row.action}</td>
                  <td className="px-5 py-3.5 text-sm font-mono text-slate-600">{row.target}</td>
                  <td className="px-5 py-3.5 text-sm text-slate-500">{row.time}</td>
                  <td className="px-5 py-3.5"><StatusBadge status={row.status} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
