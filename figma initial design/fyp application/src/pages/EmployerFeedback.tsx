import { useState } from "react";
import StatusBadge from "../components/StatusBadge";

const initial = [
  { user: "john@email.com", type: "False Positive", url: "example.com", date: "31 Aug 2026", status: "Pending" },
  { user: "sarah@email.com", type: "Incorrect Detection", url: "safe-shop.com", date: "30 Aug 2026", status: "In Review" },
  { user: "mike@email.com", type: "System Problem", url: "", date: "29 Aug 2026", status: "Responded" },
];

export default function EmployerFeedback() {
  const [items, setItems] = useState(initial);
  const [selected, setSelected] = useState<null | number>(null);
  const [reply, setReply] = useState("");

  return (
    <div className="max-w-5xl space-y-5">
      <div>
        <h2 className="text-xl font-bold text-slate-900">Feedback Management</h2>
        <p className="text-slate-500 text-sm mt-0.5">Review and respond to user feedback reports.</p>
      </div>

      <div className="bg-white rounded-xl border border-slate-200 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="text-xs text-slate-500 bg-slate-50 border-b border-slate-200">
                {["User", "Feedback Type", "URL", "Date", "Status", "Action"].map(h => (
                  <th key={h} className="text-left px-5 py-3 font-medium">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {items.map((row, i) => (
                <tr key={i} className="hover:bg-slate-50 transition-colors">
                  <td className="px-5 py-3.5 text-sm text-slate-700">{row.user}</td>
                  <td className="px-5 py-3.5 text-sm text-slate-600">{row.type}</td>
                  <td className="px-5 py-3.5 text-sm font-mono text-slate-600">{row.url || "—"}</td>
                  <td className="px-5 py-3.5 text-sm text-slate-500">{row.date}</td>
                  <td className="px-5 py-3.5"><StatusBadge status={row.status} /></td>
                  <td className="px-5 py-3.5">
                    <button onClick={() => { setSelected(i); setReply(""); }} className="text-[#1e3a5f] text-sm font-medium hover:underline">Manage</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Manage modal */}
      {selected !== null && (
        <div className="fixed inset-0 z-50 bg-black/40 flex items-center justify-center p-4">
          <div className="bg-white rounded-2xl p-6 max-w-md w-full shadow-xl space-y-4">
            <h3 className="font-semibold text-slate-900">Manage Feedback</h3>
            <div className="divide-y divide-slate-100 text-sm">
              {[
                ["User", items[selected].user],
                ["Type", items[selected].type],
                ["URL", items[selected].url || "—"],
                ["Date", items[selected].date],
              ].map(([l, v]) => (
                <div key={l} className="flex justify-between py-2">
                  <span className="text-slate-500">{l}</span>
                  <span className="text-slate-800 font-medium">{v}</span>
                </div>
              ))}
            </div>

            <div>
              <label className="block text-sm font-medium text-slate-700 mb-1.5">Change Status</label>
              <select value={items[selected].status}
                onChange={e => setItems(prev => prev.map((it, i) => i === selected ? { ...it, status: e.target.value } : it))}
                className="w-full px-3.5 py-2.5 border border-slate-300 rounded-lg text-sm bg-white focus:outline-none focus:border-[#1e3a5f]">
                <option>Pending</option>
                <option>In Review</option>
                <option>Responded</option>
                <option>Closed</option>
              </select>
            </div>

            <div>
              <label className="block text-sm font-medium text-slate-700 mb-1.5">Write Response</label>
              <textarea value={reply} onChange={e => setReply(e.target.value)} rows={3}
                placeholder="Write response..."
                className="w-full px-3.5 py-2.5 border border-slate-300 rounded-lg text-sm placeholder-slate-400 focus:outline-none focus:border-[#1e3a5f] resize-none" />
            </div>

            <div className="flex gap-3">
              <button onClick={() => setSelected(null)} className="flex-1 border border-slate-300 text-slate-700 py-2.5 rounded-lg text-sm font-medium hover:bg-slate-50">Cancel</button>
              <button onClick={() => setSelected(null)} className="flex-1 bg-[#1e3a5f] text-white py-2.5 rounded-lg text-sm font-semibold hover:bg-[#162d4a]">Send Response</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
