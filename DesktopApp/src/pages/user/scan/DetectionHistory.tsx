import { useCallback, useEffect, useState } from "react";
import { api, problem } from "../../../api";
import StatusBadge from "../../../components/StatusBadge";
import { Alert } from "../../../components/ui";
import { LEVEL_STYLE, scanTypeLabel, scoreText } from "../../../lib/analysis";
import type { ScanRecord } from "../../../lib/analysis";

interface Props {
  onOpen: (scan: ScanRecord) => void;
  onSessionEnd: () => void;
}

const PER_PAGE = 10;
const selectCls =
  "px-3.5 py-2 border border-slate-300 rounded-lg text-sm bg-white text-slate-700 focus:outline-none focus:border-[#1e3a5f]";

export default function DetectionHistory({ onOpen, onSessionEnd }: Props) {
  const [search, setSearch] = useState("");
  const [q, setQ] = useState(""); // the search text, applied 300 ms after typing stops
  const [status, setStatus] = useState("");
  const [type, setType] = useState("");
  const [page, setPage] = useState(1);
  const [rows, setRows] = useState<ScanRecord[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [confirm, setConfirm] = useState<string[] | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    const t = window.setTimeout(() => {
      setQ(search.trim());
      setPage(1);
    }, 300);
    return () => window.clearTimeout(t);
  }, [search]);

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    const qs = new URLSearchParams({ page: String(page), per_page: String(PER_PAGE) });
    if (q) qs.set("search", q);
    if (status) qs.set("status", status);
    if (type) qs.set("type", type);
    const res = await api.get(`/api/scans?${qs.toString()}`);
    setLoading(false);
    if (res.status === 401) {
      onSessionEnd();
      return;
    }
    if (res.status !== 200) {
      setError(problem(res).message);
      return;
    }
    setRows(res.data.scans as ScanRecord[]);
    setTotal(res.data.total as number);
    setSelected(new Set());
  }, [q, status, type, page]);

  useEffect(() => {
    load();
  }, [load]);

  const pages = Math.max(1, Math.ceil(total / PER_PAGE));
  const allOnPage = rows.length > 0 && rows.every((r) => selected.has(r.id));

  function toggle(id: string) {
    const next = new Set(selected);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    setSelected(next);
  }

  async function view(id: string) {
    setError("");
    const res = await api.get(`/api/scans/${id}`);
    if (res.status === 401) return onSessionEnd();
    if (res.status === 200) onOpen(res.data.scan as ScanRecord);
    else setError(problem(res).message);
  }

  async function remove() {
    if (!confirm || busy) return;
    setBusy(true);
    const res = await api.post("/api/scans/delete", { ids: confirm });
    setBusy(false);
    if (res.status === 401) return onSessionEnd();
    const removed = confirm.length;
    setConfirm(null);
    if (res.status !== 200) {
      setError(problem(res).message);
      return;
    }
    if (page > 1 && rows.length <= removed) setPage(page - 1); // the page emptied: step back (this reloads)
    else load();
  }

  function clearFilters() {
    setSearch("");
    setQ("");
    setStatus("");
    setType("");
    setPage(1);
  }

  return (
    <div className="max-w-6xl space-y-5">
      <div>
        <h2 className="text-xl font-bold text-slate-900">Detection History</h2>
        <p className="text-slate-500 text-sm mt-0.5">View and manage your previously scanned URLs.</p>
      </div>

      {error && <Alert kind="error">{error}</Alert>}

      <div className="bg-white rounded-xl border border-slate-200 p-4 flex flex-wrap gap-3">
        <input
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          aria-label="Search URL"
          maxLength={200}
          placeholder="Search URL..."
          className="flex-1 min-w-36 px-3.5 py-2 border border-slate-300 rounded-lg text-sm placeholder-slate-400 focus:outline-none focus:border-[#1e3a5f] focus:ring-2 focus:ring-[#1e3a5f]/10 transition-colors"
        />
        <select value={status} onChange={(e) => { setStatus(e.target.value); setPage(1); }} aria-label="Filter by status" className={selectCls}>
          <option value="">All Status</option>
          <option value="safe">Safe</option>
          <option value="suspicious">Suspicious</option>
          <option value="malicious">Malicious</option>
          <option value="unknown">Unknown</option>
        </select>
        <select value={type} onChange={(e) => { setType(e.target.value); setPage(1); }} aria-label="Filter by scan type" className={selectCls}>
          <option value="">All Types</option>
          <option value="auto">Automatic</option>
          <option value="manual">Manual</option>
          <option value="redirect">Redirect</option>
        </select>
        <button onClick={clearFilters} className="px-3.5 py-2 border border-slate-300 rounded-lg text-sm text-slate-600 hover:bg-slate-50 transition-colors">
          Clear Filters
        </button>
      </div>

      {selected.size > 0 && (
        <div className="flex items-center justify-between bg-blue-50 border border-blue-200 rounded-lg px-4 py-2.5 text-sm text-blue-800">
          <span>{selected.size} selected</span>
          <button onClick={() => setConfirm([...selected])} className="text-red-600 font-medium hover:underline">
            Delete selected
          </button>
        </div>
      )}

      <div className="bg-white rounded-xl border border-slate-200 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="text-xs text-slate-500 bg-slate-50 border-b border-slate-200">
                <th className="px-5 py-3 w-10">
                  <input
                    type="checkbox"
                    checked={allOnPage}
                    onChange={() => setSelected(allOnPage ? new Set() : new Set(rows.map((r) => r.id)))}
                    aria-label="Select all on this page"
                    className="w-4 h-4 accent-[#1e3a5f]"
                  />
                </th>
                {["URL", "Status", "Risk Score", "Scan Type", "Date & Time", "Action"].map((h) => (
                  <th key={h} className="text-left px-5 py-3 font-medium">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {rows.map((r) => (
                <tr key={r.id} className="hover:bg-slate-50 transition-colors">
                  <td className="px-5 py-3.5">
                    <input
                      type="checkbox"
                      checked={selected.has(r.id)}
                      onChange={() => toggle(r.id)}
                      aria-label={`Select ${r.domain}`}
                      className="w-4 h-4 accent-[#1e3a5f]"
                    />
                  </td>
                  <td className="px-5 py-3.5 text-sm font-mono text-slate-700 max-w-xs truncate" title={r.url}>
                    {r.url}
                  </td>
                  <td className="px-5 py-3.5">
                    <StatusBadge level={r.risk_level} />
                  </td>
                  <td className="px-5 py-3.5 text-sm font-semibold">
                    <span className={LEVEL_STYLE[r.risk_level].text}>{scoreText(r)}</span>
                  </td>
                  <td className="px-5 py-3.5 text-sm text-slate-600">{scanTypeLabel(r.scan_type)}</td>
                  <td className="px-5 py-3.5 text-sm text-slate-500 whitespace-nowrap">{new Date(r.scanned_at).toLocaleString()}</td>
                  <td className="px-5 py-3.5">
                    <div className="flex items-center gap-3">
                      <button onClick={() => view(r.id)} className="text-[#1e3a5f] text-sm font-medium hover:underline">
                        View
                      </button>
                      <button onClick={() => setConfirm([r.id])} className="text-red-500 text-sm font-medium hover:underline">
                        Delete
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
              {rows.length === 0 && (
                <tr>
                  <td colSpan={7} className="px-5 py-10 text-center text-slate-400 text-sm">
                    {loading ? "Loading…" : "No records found."}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {total > PER_PAGE && (
          <div className="px-5 py-3.5 border-t border-slate-100 flex items-center justify-between text-sm text-slate-600">
            <span>
              Showing {(page - 1) * PER_PAGE + 1}–{Math.min(page * PER_PAGE, total)} of {total}
            </span>
            <div className="flex gap-1">
              {Array.from({ length: pages }, (_, i) => i + 1).map((p) => (
                <button
                  key={p}
                  onClick={() => setPage(p)}
                  aria-current={p === page ? "page" : undefined}
                  className={`w-8 h-8 rounded-lg text-sm font-medium transition-colors ${
                    p === page ? "bg-[#1e3a5f] text-white" : "hover:bg-slate-100 text-slate-600"
                  }`}
                >
                  {p}
                </button>
              ))}
            </div>
          </div>
        )}
      </div>

      {confirm && (
        <div className="fixed inset-0 z-50 bg-black/40 flex items-center justify-center p-4" role="dialog" aria-modal="true" aria-labelledby="del-title">
          <div className="bg-white rounded-2xl p-6 max-w-sm w-full shadow-xl">
            <h3 id="del-title" className="font-semibold text-slate-900 mb-2">
              {confirm.length > 1 ? `Delete ${confirm.length} Detection Records?` : "Delete Detection Record?"}
            </h3>
            <p className="text-slate-500 text-sm mb-5">This action cannot be undone.</p>
            <div className="flex gap-3">
              <button onClick={() => setConfirm(null)} className="flex-1 border border-slate-300 text-slate-700 py-2.5 rounded-lg text-sm font-medium hover:bg-slate-50">
                Cancel
              </button>
              <button onClick={remove} disabled={busy} className="flex-1 bg-red-600 text-white py-2.5 rounded-lg text-sm font-medium hover:bg-red-700 disabled:opacity-60">
                {busy ? "Deleting…" : "Delete"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
