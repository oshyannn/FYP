import { useCallback, useEffect, useState } from "react";
import { api, problem } from "../../../api";
import StatusBadge from "../../../components/StatusBadge";
import { Alert } from "../../../components/ui";
import { LEVEL_STYLE, scoreText } from "../../../lib/analysis";
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

const REFRESH_MS = 5000;
const selectCls =
  "px-3.5 py-2 border border-slate-300 rounded-lg text-sm bg-white text-slate-700 focus:outline-none focus:border-[#1e3a5f]";

function timeLabel(iso: string): string {
  const d = new Date(iso);
  const t = d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  return d.toDateString() === new Date().toDateString() ? t : `${d.toLocaleDateString()} ${t}`;
}

export default function BrowserActivity({ onOpen, onSessionEnd }: Props) {
  const [rows, setRows] = useState<ScanRecord[]>([]);
  const [ext, setExt] = useState<ExtensionState | null>(null);
  const [status, setStatus] = useState("");
  const [live, setLive] = useState(true);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [rescanning, setRescanning] = useState<string | null>(null); // added: id of the row being scanned again

  // silent = the automatic refresh: no "Loading…" flash and no error banner for a single missed beat
  const load = useCallback(
    async (silent = false) => {
      if (!silent) setLoading(true);
      const qs = new URLSearchParams({ limit: "30" });
      if (status) qs.set("status", status);
      const res = await api.get(`/api/activity?${qs.toString()}`);
      setLoading(false);
      if (res.status === 401) return onSessionEnd();
      if (res.status !== 200) {
        if (!silent) setError(problem(res).message);
        return;
      }
      setError("");
      setRows(res.data.activity as ScanRecord[]);
      setExt(res.data.extension as ExtensionState);
    },
    [status, onSessionEnd],
  );

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    if (!live) return;
    const t = window.setInterval(() => {
      if (!document.hidden) load(true);
    }, REFRESH_MS);
    return () => window.clearInterval(t);
  }, [live, load]);

  async function view(id: string) {
    setError("");
    const res = await api.get(`/api/scans/${id}`);
    if (res.status === 401) return onSessionEnd();
    if (res.status === 200) onOpen(res.data.scan as ScanRecord);
    else setError(problem(res).message);
  }

  // added: scan the same address again (the detector forgets what it remembered for it) and open the new result
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

  const connected = ext?.connected ?? false;
  const paired = (ext?.paired ?? 0) > 0;

  return (
    <div className="max-w-4xl space-y-5">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-slate-900">Browser Activity</h2>
          <p className="text-slate-500 text-sm mt-0.5">URLs captured by the SafeBrowse Chrome Extension in real time.</p>
        </div>
        {ext && (
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
        )}
      </div>

      {error && <Alert kind="error">{error}</Alert>}

      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <div className={`w-2 h-2 rounded-full ${live ? "bg-red-500 animate-pulse" : "bg-slate-400"}`} />
          <span className={`text-xs font-semibold tracking-wide ${live ? "text-red-600" : "text-slate-500"}`}>
            {live ? "LIVE EXTENSION ACTIVITY" : "PAUSED"}
          </span>
          <button onClick={() => setLive(!live)} className="ml-2 text-xs text-[#1e3a5f] font-medium hover:underline">
            {live ? "Pause" : "Resume"}
          </button>
        </div>
        <select value={status} onChange={(e) => setStatus(e.target.value)} aria-label="Filter by status" className={selectCls}>
          <option value="">All Status</option>
          <option value="safe">Safe</option>
          <option value="suspicious">Suspicious</option>
          <option value="malicious">Malicious</option>
          <option value="unknown">Unknown</option>
        </select>
      </div>

      <div className="bg-white rounded-xl border border-slate-200 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="text-xs text-slate-500 bg-slate-50 border-b border-slate-200">
                {["Time", "Current URL", "Status", "Risk Score", "Action"].map((h) => (
                  <th key={h} className="text-left px-5 py-3 font-medium">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {rows.map((r) => (
                <tr key={r.id} className="hover:bg-slate-50 transition-colors">
                  <td className="px-5 py-3.5 text-sm text-slate-500 font-mono whitespace-nowrap">{timeLabel(r.scanned_at)}</td>
                  <td className="px-5 py-3.5 text-sm text-slate-700 font-mono max-w-xs truncate" title={r.url}>
                    {r.url}
                    {r.scan_type === "redirect" && <span className="ml-2 text-xs text-slate-400 font-sans">redirect</span>}
                  </td>
                  <td className="px-5 py-3.5">
                    <StatusBadge level={r.risk_level} />
                  </td>
                  <td className="px-5 py-3.5 text-sm font-semibold">
                    <span className={LEVEL_STYLE[r.risk_level].text}>{scoreText(r)}</span>
                  </td>
                  <td className="px-5 py-3.5">
                    <div className="flex items-center gap-3 whitespace-nowrap">
                      <button onClick={() => view(r.id)} className="text-[#1e3a5f] text-sm font-medium hover:underline">
                        View Details in SafeBrowse
                      </button>
                      <button
                        onClick={() => rescan(r)}
                        disabled={rescanning !== null}
                        className="text-[#1e3a5f] text-sm font-medium hover:underline disabled:opacity-50 disabled:no-underline"
                      >
                        {rescanning === r.id ? "Scanning…" : "Re-scan"}
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
              {rows.length === 0 && (
                <tr>
                  <td colSpan={5} className="px-5 py-10 text-center text-slate-400 text-sm">
                    {loading
                      ? "Loading…"
                      : paired
                        ? "No pages captured yet. Browse with Chrome and they will appear here."
                        : "No activity yet. Pair the Chrome extension with your account to start."}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      <div className="bg-blue-50 border border-blue-200 rounded-xl p-4 flex gap-3">
        <div className="text-blue-500 text-xl shrink-0">ℹ</div>
        <div>
          <p className="text-blue-800 text-sm font-medium">{connected ? "Chrome Extension Active" : "Chrome Extension"}</p>
          <p className="text-blue-600 text-xs mt-0.5">
            The SafeBrowse extension checks the pages you visit and sends the results to your account. This list shows the latest 30 and
            refreshes every few seconds{ext?.last_seen_at ? `; the extension last contacted the server at ${timeLabel(ext.last_seen_at)}` : ""}.
            The full history is in Detection History.
          </p>
        </div>
      </div>
    </div>
  );
}
