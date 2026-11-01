import { useState } from "react";
import StatusBadge from "../components/StatusBadge";

const initial = [
  { name: "Sarah Lim", company: "TechCorp Sdn Bhd", email: "sarah@techcorp.com", date: "22 Aug 2026", status: "Pending" },
  { name: "David Ng", company: "SecureNet Bhd", email: "david@securenet.com", date: "20 Aug 2026", status: "Pending" },
  { name: "Clara Tan", company: "WebShield Inc", email: "clara@webshield.com", date: "18 Aug 2026", status: "Approved" },
];

export default function EmployerVerification() {
  const [items, setItems] = useState(initial);
  const [selected, setSelected] = useState<typeof initial[0] | null>(null);
  const [confirm, setConfirm] = useState<{ action: "approve" | "reject"; idx: number } | null>(null);

  const handle = (action: "approve" | "reject", idx: number) => {
    setItems(prev => prev.map((it, i) => i === idx ? { ...it, status: action === "approve" ? "Approved" : "Rejected" } : it));
    setConfirm(null);
    setSelected(null);
  };

  return (
    <div className="max-w-4xl space-y-5">
      <div>
        <h2 className="text-xl font-bold text-slate-900">Employer Verification</h2>
        <p className="text-slate-500 text-sm mt-0.5">Review and approve employer account applications.</p>
      </div>

      {/* Stat */}
      <div className="flex gap-4">
        <div className="bg-amber-50 border border-amber-200 rounded-xl px-5 py-3">
          <span className="text-amber-700 text-sm font-semibold">{items.filter(i => i.status === "Pending").length} Pending</span>
        </div>
        <div className="bg-green-50 border border-green-200 rounded-xl px-5 py-3">
          <span className="text-green-700 text-sm font-semibold">{items.filter(i => i.status === "Approved").length} Approved</span>
        </div>
      </div>

      <div className="bg-white rounded-xl border border-slate-200 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="text-xs text-slate-500 bg-slate-50 border-b border-slate-200">
                {["Employer Name", "Company", "Email", "Submitted Date", "Status", "Action"].map(h => (
                  <th key={h} className="text-left px-5 py-3 font-medium">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {items.map((row, i) => (
                <tr key={i} className="hover:bg-slate-50 transition-colors">
                  <td className="px-5 py-3.5 text-sm font-medium text-slate-800">{row.name}</td>
                  <td className="px-5 py-3.5 text-sm text-slate-600">{row.company}</td>
                  <td className="px-5 py-3.5 text-sm text-slate-600">{row.email}</td>
                  <td className="px-5 py-3.5 text-sm text-slate-500">{row.date}</td>
                  <td className="px-5 py-3.5"><StatusBadge status={row.status} /></td>
                  <td className="px-5 py-3.5">
                    <button onClick={() => setSelected(row)} className="text-[#1e3a5f] text-sm font-medium hover:underline">Review</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {selected && (
        <div className="fixed inset-0 z-50 bg-black/40 flex items-center justify-center p-4">
          <div className="bg-white rounded-2xl p-6 max-w-sm w-full shadow-xl space-y-4">
            <h3 className="font-semibold text-slate-900">Employer Application</h3>
            <div className="divide-y divide-slate-100 text-sm">
              {[["Name", selected.name], ["Company", selected.company], ["Email", selected.email], ["Submitted", selected.date], ["Status", selected.status]].map(([l, v]) => (
                <div key={l} className="flex justify-between py-2.5">
                  <span className="text-slate-500">{l}</span>
                  <span className="text-slate-800 font-medium">{v}</span>
                </div>
              ))}
            </div>
            {selected.status === "Pending" && (
              <div className="flex gap-3 pt-1">
                <button onClick={() => setSelected(null)} className="flex-1 border border-slate-300 text-slate-700 py-2.5 rounded-lg text-sm font-medium">Cancel</button>
                <button onClick={() => { const idx = items.indexOf(selected); setConfirm({ action: "reject", idx }); }}
                  className="flex-1 border border-red-300 text-red-600 py-2.5 rounded-lg text-sm font-medium">Reject</button>
                <button onClick={() => { const idx = items.indexOf(selected); setConfirm({ action: "approve", idx }); }}
                  className="flex-1 bg-green-600 text-white py-2.5 rounded-lg text-sm font-semibold">Approve</button>
              </div>
            )}
            {selected.status !== "Pending" && (
              <button onClick={() => setSelected(null)} className="w-full border border-slate-300 text-slate-700 py-2.5 rounded-lg text-sm font-medium">Close</button>
            )}
          </div>
        </div>
      )}

      {confirm && (
        <div className="fixed inset-0 z-[60] bg-black/40 flex items-center justify-center p-4">
          <div className="bg-white rounded-2xl p-6 max-w-sm w-full shadow-xl">
            <h3 className="font-semibold text-slate-900 mb-2">Confirm {confirm.action === "approve" ? "Approval" : "Rejection"}</h3>
            <p className="text-slate-500 text-sm mb-5">Are you sure you want to {confirm.action} this employer application?</p>
            <div className="flex gap-3">
              <button onClick={() => setConfirm(null)} className="flex-1 border border-slate-300 text-slate-700 py-2.5 rounded-lg text-sm font-medium">Cancel</button>
              <button onClick={() => handle(confirm.action, confirm.idx)}
                className={`flex-1 py-2.5 rounded-lg text-sm font-semibold text-white ${confirm.action === "approve" ? "bg-green-600" : "bg-red-600"}`}>
                Confirm
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
