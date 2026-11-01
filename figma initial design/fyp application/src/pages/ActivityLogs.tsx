import StatusBadge from "../components/StatusBadge";

const logs = [
  { admin: "Admin", action: "Approved URL", target: "example.com", time: "31 Aug 2026 10:30", status: "Successful" },
  { admin: "Admin", action: "Deactivated User", target: "user@email.com", time: "31 Aug 2026 09:20", status: "Successful" },
  { admin: "Admin", action: "Verified Employer", target: "sarah@corp.com", time: "30 Aug 2026 14:05", status: "Successful" },
  { admin: "Admin", action: "Rejected URL", target: "fake-login.net", time: "30 Aug 2026 11:40", status: "Successful" },
  { admin: "Admin", action: "Blocked Threat", target: "malware-site.com", time: "29 Aug 2026 16:20", status: "Successful" },
  { admin: "Admin", action: "Updated Settings", target: "System", time: "29 Aug 2026 10:15", status: "Successful" },
  { admin: "Admin", action: "Activated User", target: "mike@email.com", time: "28 Aug 2026 09:00", status: "Successful" },
];

export default function ActivityLogs() {
  return (
    <div className="max-w-5xl space-y-5">
      <div>
        <h2 className="text-xl font-bold text-slate-900">Admin Activity Logs</h2>
        <p className="text-slate-500 text-sm mt-0.5">Complete audit trail of admin actions.</p>
      </div>

      <div className="bg-white rounded-xl border border-slate-200 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="text-xs text-slate-500 bg-slate-50 border-b border-slate-200">
                {["Admin", "Action", "Target", "Date/Time", "Status"].map(h => (
                  <th key={h} className="text-left px-5 py-3 font-medium">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {logs.map((row, i) => (
                <tr key={i} className="hover:bg-slate-50 transition-colors">
                  <td className="px-5 py-3.5 text-sm font-medium text-slate-800">{row.admin}</td>
                  <td className="px-5 py-3.5 text-sm text-slate-700">{row.action}</td>
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
