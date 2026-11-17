import { useCallback, useEffect, useState } from "react";
import { api, problem } from "../../../api";
import Pager from "../../../components/Pager";
import StatusBadge from "../../../components/StatusBadge";
import { Alert } from "../../../components/ui";
import { LEVEL_STYLE, scanTypeLabel, scoreText } from "../../../lib/analysis";
import type { ScanRecord } from "../../../lib/analysis";

interface Props {
  onOpen: (scan: ScanRecord) => void;
  onSessionEnd: () => void;
}

interface ExtensionState {
  paired: number;
  connected: boolean;
  last_seen_at: string | null;
}

const PER_PAGE = 10;
const REFRESH_MS = 5000;
const selectCls =
  "px-3.5 py-2 border border-slate-300 rounded-lg text-sm bg-white text-slate-700 focus:outline-none focus:border-[#1e3a5f]";

function timeLabel(iso: string): string {
  const d = new Date(iso);
  const t = d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  return d.toDateString() === new Date().toDateString() ? t : `${d.toLocaleDateString()} ${t}`;
}

// Combined Detection History & Live Chrome Extension Browser Activity, with Save URL support.
export default function DetectionHistory({ onOpen, onSessionEnd }: Props) {
  const [search, setSearch] = useState("");
  const [q, setQ] = useState("");
  const [status, setStatus] = useState("");
  const [type, setType] = useState("");
  const [page, setPage] = useState(1);

  const [rows, setRows] = useState<ScanRecord[]>([]);
  const [total, setTotal] = useState(0);
  const [ext, setExt] = useState<ExtensionState | null>(null);
  const [live, setLive] = useState(true);

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [confirm, setConfirm] = useState<string[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [rescanning, setRescanning] = useState<string | null>(null);
  const [savingId, setSavingId] = useState<string | null>(null);

  useEffect(() => {
    const t = window.setTimeout(() => {
      setQ(search.trim());
      setPage(1);
    }, 300);
    return () => window.clearTimeout(t);
  }, [search]);

  const load = useCallback(
    async (silent = false) => {
      if (!silent) setLoading(true);
      if (!silent) setError("");
      const qs = new URLSearchParams({ page: String(page), per_page: String(PER_PAGE) });
      if (q) qs.set("search", q);
      if (status) qs.set("status", status);
      if (type) qs.set("type", type);
      const [scansRes, actRes] = await Promise.all([
        api.get(`/api/scans?${qs.toString()}`),
        page === 1 ? api.get("/api/activity?limit=1") : Promise.resolve(null),
      ]);
      setLoading(false);
      if (scansRes.status === 401 || actRes?.status === 401) {
        onSessionEnd();
        return;
      }
      if (scansRes.status !== 200) {
        if (!silent) setError(problem(scansRes).message);
        return;
      }
      setRows(scansRes.data.scans as ScanRecord[]);
      setTotal(scansRes.data.total as number);
      if (!silent) setSelected(new Set());
      if (actRes && actRes.status === 200 && actRes.data.extension) {
        setExt(actRes.data.extension as ExtensionState);
      }
    },
    [q, status, type, page, onSessionEnd],
  );

  useEffect(() => {
    load();
  }, [load]);

  // Live auto-refresh when enabled and viewing page 1
  useEffect(() => {
    if (!live || page !== 1) return;
    const t = window.setInterval(() => {
      if (!document.hidden) load(true);
    }, REFRESH_MS);
    return () => window.clearInterval(t);
  }, [live, page, load]);

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

  async function rescan(r: ScanRecord) {
    if (rescanning) return;
    setError("");
    setRescanning(r.id);
    const res = await api.post("/api/scans", { url: r.url, fresh: true });
    setRescanning(null);
    if (res.status === 401) return onSessionEnd();
    if (res.status === 201) onOpen(res.data.scan as ScanRecord);
    else setError(res.status === 429 ? "Too many scans in a short time. Wait a moment and try again." : problem(res).message);
  }

  async function toggleSave(r: ScanRecord) {
    if (savingId) return;
    setSavingId(r.id);
    setError("");
    setNotice("");
    if (r.is_saved) {
      const res = await api.del(`/api/saved-urls?url=${encodeURIComponent(r.url)}`);
      setSavingId(null);
      if (res.status === 401) return onSessionEnd();
      if (res.status === 200 || res.status === 404) {
        setRows((list) => list.map((x) => (x.url === r.url ? { ...x, is_saved: false } : x)));
        setNotice(`${r.domain} removed from Saved URLs.`);
      } else {
        setError(problem(res).message);
      }
    } else {
      const res = await api.post("/api/saved-urls", {
        url: r.url,
        risk_level: r.risk_level,
        risk_score: r.risk_score,
      });
      setSavingId(null);
      if (res.status === 401) return onSessionEnd();
      if (res.status === 201 || res.status === 200) {
        setRows((list) => list.map((x) => (x.url === r.url ? { ...x, is_saved: true } : x)));
        setNotice(`${r.domain} saved to Saved URLs.`);
      } else {
        setError(problem(res).message);
      }
    }
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
    if (page > 1 && rows.length <= removed) setPage(page - 1);
    else load();
  }

  function clearFilters() {
    setSearch("");
    setQ("");
    setStatus("");
    setType("");
    setPage(1);
  }

  const connected = ext?.connected ?? false;
  const paired = (ext?.paired ?? 0) > 0;

  return (
    <div className="max-w-6xl space-y-5">
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h2 className="text-xl font-bold text-slate-900">Detection History</h2>
          <p className="text-slate-500 text-sm mt-0.5">
            All scanned URLs and real-time Chrome Extension activity in one unified view.
          </p>
        </div>
        {ext && (
          <div className="flex items-center gap-3 flex-wrap">
            <div
              className={`flex items-center gap-2 px-3 py-1.5 rounded-full border shrink-0 ${
                connected ? "bg-green-50 border-green-200" : paired ? "bg-amber-50 border-amber-200" : "bg-slate-100 border-slate-200"
              }`}
            >
              <div className={`w-2 h-2 rounded-full ${connected ? "bg-green-500 animate-pulse" : paired ? "bg-amber-500" : "bg-slate-400"}`} />
              <span className={`text-xs font-medium ${connected ? "text-green-700" : paired ? "text-amber-700" : "text-slate-600"}`}>
                {connected ? "Extension Connected" : paired ? "Extension Idle" : "Extension Not Connected"}
              </span>
            </div>
            <div className="flex items-center gap-2 px-3 py-1.5 rounded-full border border-slate-200 bg-white">
              <div className={`w-2 h-2 rounded-full ${live ? "bg-red-500 animate-pulse" : "bg-slate-400"}`} />
              <span className={`text-xs font-semibold ${live ? "text-red-600" : "text-slate-500"}`}>
                {live ? "LIVE" : "PAUSED"}
              </span>
              <button type="button" onClick={() => setLive(!live)} className="text-xs text-[#1e3a5f] font-medium hover:underline">
                {live ? "Pause" : "Resume"}
              </button>
            </div>
          </div>
        )}
      </div>

      {error && <Alert kind="error">{error}</Alert>}
      {notice && <Alert kind="success">{notice}</Alert>}

      <div className="bg-white rounded-xl border border-slate-200 p-4 flex flex-wrap gap-3">
        <input
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          aria-label="Search URL"
          maxLength={200}
          placeholder="Search URL or domain..."
          className="flex-1 min-w-44 px-3.5 py-2 border border-slate-300 rounded-lg text-sm placeholder-slate-400 focus:outline-none focus:border-[#1e3a5f] focus:ring-2 focus:ring-[#1e3a5f]/10 transition-colors"
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
          <option value="auto">Automatic (Extension)</option>
          <option value="manual">Manual Scan</option>
          <option value="redirect">Redirect</option>
        </select>
        <button type="button" onClick={clearFilters} className="px-3.5 py-2 border border-slate-300 rounded-lg text-sm text-slate-600 hover:bg-slate-50 transition-colors">
          Clear Filters
        </button>
      </div>

      {selected.size > 0 && (
        <div className="flex items-center justify-between bg-blue-50 border border-blue-200 rounded-lg px-4 py-2.5 text-sm text-blue-800">
          <span>{selected.size} selected</span>
          <button type="button" onClick={() => setConfirm([...selected])} className="text-red-600 font-medium hover:underline">
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
                {["URL", "Status", "Risk Score", "Scan Type", "Date & Time", "Actions"].map((h) => (
                  <th key={h} className="text-left px-5 py-3 font-medium whitespace-nowrap">
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
                  <td className="px-5 py-3.5 text-sm text-slate-500 whitespace-nowrap">{timeLabel(r.scanned_at)}</td>
                  <td className="px-5 py-3.5">
                    <div className="flex items-center gap-3 whitespace-nowrap">
                      <button
                        type="button"
                        onClick={() => toggleSave(r)}
                        disabled={savingId === r.id}
                        title={r.is_saved ? "Remove from Saved URLs" : "Save to Saved URLs"}
                        className={`text-sm font-medium transition-colors ${
                          r.is_saved ? "text-amber-600 hover:text-amber-700" : "text-slate-500 hover:text-[#1e3a5f]"
                        }`}
                      >
                        {r.is_saved ? "★ Saved" : "☆ Save"}
                      </button>
                      <button type="button" onClick={() => view(r.id)} className="text-[#1e3a5f] text-sm font-medium hover:underline">
                        View
                      </button>
                      <button
                        type="button"
                        onClick={() => rescan(r)}
                        disabled={rescanning !== null}
                        className="text-[#1e3a5f] text-sm font-medium hover:underline disabled:opacity-50 disabled:no-underline"
                      >
                        {rescanning === r.id ? "Scanning…" : "Re-scan"}
                      </button>
                      <button type="button" onClick={() => setConfirm([r.id])} className="text-red-500 text-sm font-medium hover:underline">
                        Delete
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
              {rows.length === 0 && (
                <tr>
                  <td colSpan={7} className="px-5 py-10 text-center text-slate-400 text-sm">
                    {loading
                      ? "Loading…"
                      : paired
                        ? "No detection records found. Browse with Chrome or scan a URL to see results here."
                        : "No records found."}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
        <Pager page={page} perPage={PER_PAGE} total={total} onPage={setPage} />
      </div>

      {ext && (
        <div className="bg-blue-50 border border-blue-200 rounded-xl p-4 flex gap-3">
          <div className="text-blue-500 text-xl shrink-0">ℹ</div>
          <div>
            <p className="text-blue-800 text-sm font-medium">{connected ? "Chrome Extension Active" : "Chrome Extension"}</p>
            <p className="text-blue-600 text-xs mt-0.5">
              Pages visited in Chrome are automatically scanned and streamed here in real time
              {ext.last_seen_at ? ` (last contacted server at ${timeLabel(ext.last_seen_at)})` : ""}.
            </p>
          </div>
        </div>
      )}

      {confirm && (
        <div className="fixed inset-0 z-50 bg-black/40 flex items-center justify-center p-4" role="dialog" aria-modal="true" aria-labelledby="del-title">
          <div className="bg-white rounded-2xl p-6 max-w-sm w-full shadow-xl">
            <h3 id="del-title" className="font-semibold text-slate-900 mb-2">
              {confirm.length > 1 ? `Delete ${confirm.length} Detection Records?` : "Delete Detection Record?"}
            </h3>
            <p className="text-slate-500 text-sm mb-5">This action cannot be undone.</p>
            <div className="flex gap-3">
              <button type="button" onClick={() => setConfirm(null)} className="flex-1 border border-slate-300 text-slate-700 py-2.5 rounded-lg text-sm font-medium hover:bg-slate-50">
                Cancel
              </button>
              <button type="button" onClick={remove} disabled={busy} className="flex-1 bg-red-600 text-white py-2.5 rounded-lg text-sm font-medium hover:bg-red-700 disabled:opacity-60">
                {busy ? "Deleting…" : "Delete"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
