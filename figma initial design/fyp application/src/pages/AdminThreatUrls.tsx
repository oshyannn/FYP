import { useState } from "react";
import StatusBadge from "../components/StatusBadge";
import type { ThreatEntry } from "../threatStore";

interface Props {
  threats: ThreatEntry[];
  onRemove: (id: number) => void;
}

export default function AdminThreatUrls({ threats, onRemove }: Props) {
  const [selected, setSelected] = useState<ThreatEntry | null>(null);
  const [action, setAction] = useState<"block" | "remove" | null>(null);
  const [search, setSearch] = useState("");

  const stats = [
    { label: "Total Threats", value: threats.length, color: "text-slate-800" },
    { label: "Phishing", value: threats.filter(i => i.type === "Phishing").length, color: "text-orange-600" },
    { label: "Malware", value: threats.filter(i => i.type === "Malware").length, color: "text-red-600" },
    { label: "Suspicious", value: threats.filter(i => i.type === "Suspicious" || i.type === "Scam" || i.type === "Spam").length, color: "text-amber-600" },
  ];

  const filtered = threats.filter(t => t.url.toLowerCase().includes(search.toLowerCase()));
  const scoreColor = (s: number) => s < 30 ? "text-green-600" : s < 70 ? "text-amber-600" : "text-red-600";

  return (
    <div className="max-w-5xl space-y-5">
      <div>
        <h2 className="text-xl font-bold text-slate-900">Threat URL Management</h2>
        <p className="text-slate-500 text-sm mt-0.5">Monitor and manage the Global Threat URL List.</p>
      </div>

      <div className="grid grid-cols-4 gap-4">
        {stats.map(s => (
          <div key={s.label} className="bg-white rounded-xl border border-slate-200 p-4 text-center">
            <div className={`text-2xl font-bold ${s.color}`}>{s.value}</div>
            <div className="text-slate-500 text-xs mt-1">{s.label}</div>
          </div>
        ))}
      </div>

      <div className="flex gap-3">
        <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search threat URL..."
          className="flex-1 px-3.5 py-2 border border-slate-300 rounded-lg text-sm placeholder-slate-400 bg-white focus:outline-none focus:border-[#1e3a5f] focus:ring-2 focus:ring-[#1e3a5f]/10" />
      </div>

      <div className="bg-white rounded-xl border border-slate-200 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="text-xs text-slate-500 bg-slate-50 border-b border-slate-200">
                {["URL", "Category", "Risk Score", "Detection Source", "Status", "Date", "Action"].map(h => (
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
                  <td className="px-5 py-3.5 text-sm text-slate-600">{row.source}</td>
                  <td className="px-5 py-3.5"><StatusBadge status={row.status} /></td>
                  <td className="px-5 py-3.5 text-sm text-slate-500">{row.date}</td>
                  <td className="px-5 py-3.5">
                    <div className="flex gap-3">
                      <button onClick={() => { setSelected(row); setAction(null); }} className="text-[#1e3a5f] text-sm font-medium hover:underline">View</button>
                      <button onClick={() => { setSelected(row); setAction("remove"); }} className="text-red-500 text-sm font-medium hover:underline">Remove</button>
                    </div>
                  </td>
                </tr>
              ))}
              {filtered.length === 0 && (
                <tr><td colSpan={7} className="px-5 py-10 text-center text-slate-400 text-sm">No threat URLs found.</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* View modal */}
      {selected && !action && (
        <div className="fixed inset-0 z-50 bg-black/40 flex items-center justify-center p-4">
          <div className="bg-white rounded-2xl shadow-xl w-full max-w-md">
            <div className="flex items-center justify-between px-6 py-5 border-b border-slate-100">
              <h3 className="font-semibold text-slate-900">Threat URL Details</h3>
              <button onClick={() => setSelected(null)} className="text-slate-400 hover:text-slate-600 text-2xl leading-none">×</button>
            </div>
            <div className="px-6 py-5 divide-y divide-slate-100">
              {([
                ["URL", <span className="font-mono text-xs text-slate-800 break-all">{selected.url}</span>],
                ["Type", <StatusBadge status={selected.type} />],
                ["Risk Score", <span className={`font-bold ${scoreColor(selected.score)}`}>{selected.score}/100</span>],
                ["Status", <StatusBadge status={selected.status} />],
                ["Source", <span className="text-slate-700">{selected.source}</span>],
                ["Date", <span className="text-slate-700">{selected.date}</span>],
              ] as [string, React.ReactNode][]).map(([l, v]) => (
                <div key={l} className="flex items-center justify-between py-3 text-sm gap-4">
                  <span className="text-slate-500 shrink-0">{l}</span><div className="text-right">{v}</div>
                </div>
              ))}
              <div className="py-3">
                <p className="text-slate-500 text-sm mb-1.5">Notes</p>
                <p className="text-slate-700 text-sm leading-relaxed">{selected.notes}</p>
              </div>
            </div>
            <div className="px-6 py-4 border-t border-slate-100 flex gap-3">
              <button onClick={() => setSelected(null)} className="flex-1 border border-slate-300 text-slate-700 py-2.5 rounded-lg text-sm font-medium hover:bg-slate-50">Close</button>
              <button onClick={() => setAction("remove")} className="flex-1 border border-red-300 text-red-600 py-2.5 rounded-lg text-sm font-medium hover:bg-red-50">Remove from List</button>
            </div>
          </div>
        </div>
      )}

      {/* Remove confirm */}
      {selected && action === "remove" && (
        <div className="fixed inset-0 z-[60] bg-black/40 flex items-center justify-center p-4">
          <div className="bg-white rounded-2xl p-6 max-w-sm w-full shadow-xl">
            <h3 className="font-semibold text-slate-900 mb-2">Remove from Threat List?</h3>
            <p className="text-slate-500 text-sm mb-1 font-mono">{selected.url}</p>
            <p className="text-slate-500 text-sm mb-5">This URL will be removed from the Global Threat List and will no longer be blocked for users.</p>
            <div className="flex gap-3">
              <button onClick={() => { setSelected(null); setAction(null); }}
                className="flex-1 border border-slate-300 text-slate-700 py-2.5 rounded-lg text-sm font-medium">Cancel</button>
              <button onClick={() => { onRemove(selected.id); setSelected(null); setAction(null); }}
                className="flex-1 bg-red-600 text-white py-2.5 rounded-lg text-sm font-medium hover:bg-red-700">Remove</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
