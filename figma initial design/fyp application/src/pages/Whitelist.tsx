import { useState } from "react";

const initial = [
  { domain: "example.com", added: "31 Aug 2026", by: "User" },
  { domain: "university.edu", added: "30 Aug 2026", by: "User" },
  { domain: "gov.my", added: "29 Aug 2026", by: "User" },
];

export default function Whitelist() {
  const [items, setItems] = useState(initial);
  const [input, setInput] = useState("");
  const [removeTarget, setRemoveTarget] = useState<number | null>(null);

  const add = () => {
    if (!input.trim()) return;
    setItems(prev => [...prev, { domain: input.trim(), added: "31 Aug 2026", by: "User" }]);
    setInput("");
  };

  return (
    <div className="max-w-3xl space-y-5">
      <div>
        <h2 className="text-xl font-bold text-slate-900">Trusted Websites</h2>
        <p className="text-slate-500 text-sm mt-0.5">Websites added to the whitelist will be treated as trusted by SafeBrowse.</p>
      </div>

      {/* Add */}
      <div className="bg-white rounded-xl border border-slate-200 p-5">
        <h3 className="font-semibold text-slate-800 mb-3">Add Trusted Website</h3>
        <div className="flex gap-3">
          <input value={input} onChange={e => setInput(e.target.value)} onKeyDown={e => e.key === "Enter" && add()}
            placeholder="Enter URL or domain, e.g. example.com"
            className="flex-1 px-3.5 py-2.5 border border-slate-300 rounded-lg text-sm placeholder-slate-400 focus:outline-none focus:border-[#1e3a5f] focus:ring-2 focus:ring-[#1e3a5f]/10 transition-colors" />
          <button onClick={add}
            className="bg-[#1e3a5f] text-white px-5 py-2.5 rounded-lg text-sm font-semibold hover:bg-[#162d4a] transition-colors">
            + Add
          </button>
        </div>
      </div>

      {/* Table */}
      <div className="bg-white rounded-xl border border-slate-200 overflow-hidden">
        <div className="px-5 py-4 border-b border-slate-100">
          <h3 className="font-semibold text-slate-800">Trusted Domains ({items.length})</h3>
        </div>
        <table className="w-full">
          <thead>
            <tr className="text-xs text-slate-500 bg-slate-50 border-b border-slate-200">
              {["Domain", "Added Date", "Added By", "Action"].map(h => (
                <th key={h} className="text-left px-5 py-3 font-medium">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {items.map((row, i) => (
              <tr key={i} className="hover:bg-slate-50 transition-colors">
                <td className="px-5 py-3.5 text-sm font-mono text-slate-700">{row.domain}</td>
                <td className="px-5 py-3.5 text-sm text-slate-600">{row.added}</td>
                <td className="px-5 py-3.5 text-sm text-slate-600">{row.by}</td>
                <td className="px-5 py-3.5">
                  <button onClick={() => setRemoveTarget(i)} className="text-red-500 text-sm font-medium hover:underline">Remove</button>
                </td>
              </tr>
            ))}
            {items.length === 0 && (
              <tr><td colSpan={4} className="px-5 py-10 text-center text-slate-400 text-sm">No trusted websites added.</td></tr>
            )}
          </tbody>
        </table>
      </div>

      {/* Confirm modal */}
      {removeTarget !== null && (
        <div className="fixed inset-0 z-50 bg-black/40 flex items-center justify-center p-4">
          <div className="bg-white rounded-2xl p-6 max-w-sm w-full shadow-xl">
            <h3 className="font-semibold text-slate-900 mb-2">Remove Trusted Website?</h3>
            <p className="text-slate-500 text-sm mb-1 font-mono">{items[removeTarget]?.domain}</p>
            <p className="text-slate-500 text-sm mb-5">This domain will no longer be trusted by SafeBrowse.</p>
            <div className="flex gap-3">
              <button onClick={() => setRemoveTarget(null)}
                className="flex-1 border border-slate-300 text-slate-700 py-2.5 rounded-lg text-sm font-medium hover:bg-slate-50">Cancel</button>
              <button onClick={() => { setItems(r => r.filter((_, i) => i !== removeTarget)); setRemoveTarget(null); }}
                className="flex-1 bg-red-600 text-white py-2.5 rounded-lg text-sm font-medium hover:bg-red-700">Remove</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
