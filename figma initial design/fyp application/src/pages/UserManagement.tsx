import { useState } from "react";
import StatusBadge from "../components/StatusBadge";

const allUsers = [
  { name: "John Tan", email: "john@email.com", role: "User", status: "Active", date: "20 Aug 2026" },
  { name: "Sarah Lim", email: "sarah@email.com", role: "Employer", status: "Pending", date: "22 Aug 2026" },
  { name: "Mike Wong", email: "mike@email.com", role: "User", status: "Active", date: "18 Aug 2026" },
  { name: "Anna Chen", email: "anna@email.com", role: "User", status: "Inactive", date: "15 Aug 2026" },
  { name: "David Ng", email: "david@email.com", role: "Employer", status: "Active", date: "10 Aug 2026" },
];

export default function UserManagement() {
  const [search, setSearch] = useState("");
  const [filterRole, setFilterRole] = useState("all");
  const [filterStatus, setFilterStatus] = useState("all");
  const [users, setUsers] = useState(allUsers);
  const [selected, setSelected] = useState<typeof allUsers[0] | null>(null);

  const filtered = users.filter(u =>
    (u.name.toLowerCase().includes(search.toLowerCase()) || u.email.toLowerCase().includes(search.toLowerCase())) &&
    (filterRole === "all" || u.role.toLowerCase() === filterRole) &&
    (filterStatus === "all" || u.status.toLowerCase() === filterStatus)
  );

  const toggleStatus = (email: string) => {
    setUsers(prev => prev.map(u => u.email === email
      ? { ...u, status: u.status === "Active" ? "Inactive" : "Active" }
      : u));
    setSelected(null);
  };

  return (
    <div className="max-w-5xl space-y-5">
      <div>
        <h2 className="text-xl font-bold text-slate-900">User Management</h2>
        <p className="text-slate-500 text-sm mt-0.5">Manage user accounts and permissions.</p>
      </div>

      <div className="flex flex-wrap gap-3">
        <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search user..."
          className="flex-1 min-w-48 px-3.5 py-2 border border-slate-300 rounded-lg text-sm placeholder-slate-400 bg-white focus:outline-none focus:border-[#1e3a5f] focus:ring-2 focus:ring-[#1e3a5f]/10" />
        <select value={filterRole} onChange={e => setFilterRole(e.target.value)}
          className="px-3.5 py-2 border border-slate-300 rounded-lg text-sm bg-white text-slate-700 focus:outline-none focus:border-[#1e3a5f]">
          <option value="all">All Roles</option>
          <option value="user">User</option>
          <option value="employer">Employer</option>
        </select>
        <select value={filterStatus} onChange={e => setFilterStatus(e.target.value)}
          className="px-3.5 py-2 border border-slate-300 rounded-lg text-sm bg-white text-slate-700 focus:outline-none focus:border-[#1e3a5f]">
          <option value="all">All Status</option>
          <option value="active">Active</option>
          <option value="inactive">Inactive</option>
          <option value="pending">Pending</option>
        </select>
      </div>

      <div className="bg-white rounded-xl border border-slate-200 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="text-xs text-slate-500 bg-slate-50 border-b border-slate-200">
                {["Name", "Email", "Role", "Status", "Registration Date", "Action"].map(h => (
                  <th key={h} className="text-left px-5 py-3 font-medium">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {filtered.map((row, i) => (
                <tr key={i} className="hover:bg-slate-50 transition-colors">
                  <td className="px-5 py-3.5 text-sm font-medium text-slate-800">{row.name}</td>
                  <td className="px-5 py-3.5 text-sm text-slate-600">{row.email}</td>
                  <td className="px-5 py-3.5 text-sm text-slate-600">{row.role}</td>
                  <td className="px-5 py-3.5"><StatusBadge status={row.status} /></td>
                  <td className="px-5 py-3.5 text-sm text-slate-500">{row.date}</td>
                  <td className="px-5 py-3.5">
                    <button onClick={() => setSelected(row)} className="text-[#1e3a5f] text-sm font-medium hover:underline">Manage</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Manage modal */}
      {selected && (
        <div className="fixed inset-0 z-50 bg-black/40 flex items-center justify-center p-4">
          <div className="bg-white rounded-2xl p-6 max-w-sm w-full shadow-xl space-y-4">
            <h3 className="font-semibold text-slate-900">Manage User</h3>
            <div className="divide-y divide-slate-100 text-sm">
              {[["Name", selected.name], ["Email", selected.email], ["Role", selected.role], ["Status", selected.status]].map(([l, v]) => (
                <div key={l} className="flex justify-between py-2.5">
                  <span className="text-slate-500">{l}</span>
                  <span className="text-slate-800 font-medium">{v}</span>
                </div>
              ))}
            </div>
            <div className="flex flex-col gap-2 pt-1">
              <button className="w-full border border-slate-300 text-slate-700 py-2.5 rounded-lg text-sm font-medium hover:bg-slate-50">View Account</button>
              <button className="w-full border border-slate-300 text-slate-700 py-2.5 rounded-lg text-sm font-medium hover:bg-slate-50">Edit Account</button>
              <button onClick={() => toggleStatus(selected.email)}
                className={`w-full py-2.5 rounded-lg text-sm font-semibold text-white transition-colors ${selected.status === "Active" ? "bg-red-600 hover:bg-red-700" : "bg-green-600 hover:bg-green-700"}`}>
                {selected.status === "Active" ? "Deactivate Account" : "Activate Account"}
              </button>
              <button onClick={() => setSelected(null)} className="w-full border border-slate-300 text-slate-700 py-2.5 rounded-lg text-sm font-medium hover:bg-slate-50">Cancel</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
