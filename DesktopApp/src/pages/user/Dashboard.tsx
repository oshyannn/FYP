import { useEffect, useState } from "react";
import { api, problem } from "../../api";
import StatusBadge from "../../components/StatusBadge";
import { Alert, SecondaryButton } from "../../components/ui";
import { LEVEL_STYLE, scanTypeLabel, scoreText } from "../../lib/analysis";
import type { ScanRecord } from "../../lib/analysis";
import type { UserStats } from "../../lib/dashboard";

interface Device {
  id: string;
  label: string | null;
  paired_at: string;
  last_seen_at: string;
}

interface Props {
  name: string;
  onSessionEnd: () => void;
  onScanned: (scan: ScanRecord) => void;
  onOpen: (scan: ScanRecord) => void;
  onViewAll: () => void;
}

export default function Dashboard({ name, onSessionEnd, onScanned, onOpen, onViewAll }: Props) {
  const [stats, setStats] = useState<UserStats | null>(null);
  const [recent, setRecent] = useState<ScanRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const [url, setUrl] = useState("");
  const [scanning, setScanning] = useState(false);
  const [scanError, setScanError] = useState("");

  const [pairError, setPairError] = useState("");
  const [pair, setPair] = useState<{ code: string; expiresAt: number } | null>(null);
  const [left, setLeft] = useState(0);
  const [devices, setDevices] = useState<Device[]>([]);

  const ended = (s: number) => {
    if (s === 401) {
      onSessionEnd();
      return true;
    }
    return false;
  };

  useEffect(() => {
    (async () => {
      const res = await api.get("/api/dashboard");
      setLoading(false);
      if (ended(res.status)) return;
      if (res.status === 200) {
        setStats(res.data.stats as UserStats);
        setRecent(res.data.recent as ScanRecord[]);
      } else setError(problem(res).message);
    })();
    loadDevices();
  }, []);

  async function loadDevices() {
    const res = await api.get("/api/extension/devices");
    if (ended(res.status)) return;
    if (res.status === 200) setDevices(res.data.devices);
  }

  useEffect(() => {
    if (!pair) return;
    const tick = () => {
      const s = Math.max(0, Math.round((pair.expiresAt - Date.now()) / 1000));
      setLeft(s);
      if (s === 0) setPair(null);
    };
    tick();
    const id = window.setInterval(tick, 1000);
    return () => window.clearInterval(id);
  }, [pair]);

  async function quickScan() {
    if (!url.trim() || scanning) return;
    setScanning(true);
    setScanError("");
    const res = await api.post("/api/scans", { url: url.trim() });
    setScanning(false);
    if (ended(res.status)) return;
    if (res.status === 201) return onScanned(res.data.scan as ScanRecord);
    const p = problem(res);
    setScanError(res.status === 429 ? "Too many scans in a short time. Wait a moment and try again." : (p.fields.url ?? p.message));
  }

  async function view(id: string) {
    const res = await api.get(`/api/scans/${id}`);
    if (ended(res.status)) return;
    if (res.status === 200) onOpen(res.data.scan as ScanRecord);
    else setError(problem(res).message);
  }

  async function generate() {
    setPairError("");
    const res = await api.post("/api/extension/pairing-code");
    if (ended(res.status)) return;
    if (res.status === 200) setPair({ code: res.data.code, expiresAt: Date.now() + res.data.expires_in * 1000 });
    else setPairError(problem(res).message);
  }

  async function disconnect(id: string) {
    const res = await api.del(`/api/extension/devices/${id}`);
    if (ended(res.status)) return;
    loadDevices();
  }

  const cards = [
    { label: "Total Scanned", value: stats?.total, icon: "🔍", color: "text-[#1e3a5f]", bg: "bg-blue-50", note: stats && stats.unknown > 0 ? `includes ${stats.unknown} unknown` : "" },
    { label: "Safe URLs", value: stats?.safe, icon: "✓", color: "text-green-600", bg: "bg-green-50", note: "" },
    { label: "Suspicious", value: stats?.suspicious, icon: "⚠", color: "text-amber-600", bg: "bg-amber-50", note: "" },
    { label: "Malicious", value: stats?.malicious, icon: "✗", color: "text-red-600", bg: "bg-red-50", note: "" },
  ];

  return (
    <div className="space-y-6 max-w-6xl">
      <div>
        <h2 className="text-xl font-bold text-slate-900">Welcome back, {name}!</h2>
        <p className="text-slate-500 text-sm mt-0.5">SafeBrowse is protecting your browsing activity.</p>
      </div>

      {error && <Alert kind="error">{error}</Alert>}

      <div className="grid grid-cols-4 gap-4">
        {cards.map((c) => (
          <div key={c.label} className="bg-white rounded-xl border border-slate-200 p-5">
            <div className={`w-9 h-9 ${c.bg} rounded-lg flex items-center justify-center text-base mb-3 ${c.color}`}>{c.icon}</div>
            <div className={`text-2xl font-bold ${c.color}`}>{c.value ?? "–"}</div>
            <div className="text-slate-500 text-xs mt-1">{c.label}</div>
            {c.note && <div className="text-slate-400 text-[11px] mt-0.5">{c.note}</div>}
          </div>
        ))}
      </div>

      <div className="bg-white rounded-xl border border-slate-200 p-6">
        <h3 className="font-semibold text-slate-800 mb-1">Quick URL Scan</h3>
        <p className="text-slate-500 text-sm mb-4">Check a website before visiting it.</p>
        {scanError && <Alert kind="error">{scanError}</Alert>}
        <div className="flex gap-3">
          <label htmlFor="quick-url" className="sr-only">Website URL</label>
          <input
            id="quick-url"
            value={url}
            maxLength={2048}
            onChange={(e) => setUrl(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && quickScan()}
            placeholder="Enter URL, e.g. https://example.com"
            className="flex-1 px-4 py-2.5 border border-slate-300 rounded-lg text-sm placeholder-slate-400 focus:outline-none focus:border-[#1e3a5f] focus:ring-2 focus:ring-[#1e3a5f]/10 transition-colors"
          />
          <button
            onClick={quickScan}
            disabled={scanning || !url.trim()}
            className="bg-[#1e3a5f] text-white px-5 py-2.5 rounded-lg text-sm font-semibold hover:bg-[#162d4a] disabled:opacity-50 disabled:cursor-not-allowed transition-colors whitespace-nowrap"
          >
            {scanning ? "Scanning…" : "Scan URL"}
          </button>
        </div>
      </div>

      <div className="bg-white rounded-xl border border-slate-200">
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-100">
          <h3 className="font-semibold text-slate-800">Recent Detection Activity</h3>
          <button onClick={onViewAll} className="text-sm text-[#1e3a5f] hover:underline font-medium">View All</button>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="text-xs text-slate-500 bg-slate-50">
                {["URL", "Status", "Risk Score", "Detection Type", "Time", "Action"].map((h) => (
                  <th key={h} className="text-left px-6 py-3 font-medium">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {recent.map((r) => (
                <tr key={r.id} className="hover:bg-slate-50 transition-colors">
                  <td className="px-6 py-3.5 text-sm text-slate-700 font-mono max-w-xs truncate" title={r.url}>{r.url}</td>
                  <td className="px-6 py-3.5"><StatusBadge level={r.risk_level} /></td>
                  <td className="px-6 py-3.5 text-sm font-semibold"><span className={LEVEL_STYLE[r.risk_level].text}>{scoreText(r)}</span></td>
                  <td className="px-6 py-3.5 text-sm text-slate-600">{scanTypeLabel(r.scan_type)}</td>
                  <td className="px-6 py-3.5 text-sm text-slate-500 whitespace-nowrap">{new Date(r.scanned_at).toLocaleString()}</td>
                  <td className="px-6 py-3.5">
                    <button onClick={() => view(r.id)} className="text-[#1e3a5f] text-sm font-medium hover:underline">View</button>
                  </td>
                </tr>
              ))}
              {recent.length === 0 && (
                <tr>
                  <td colSpan={6} className="px-6 py-8 text-center text-slate-400 text-sm">
                    {loading ? "Loading…" : "No scans yet. Scan your first URL above."}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      <div className="bg-white rounded-xl border border-slate-200 p-6">
        <h3 className="font-semibold text-slate-800">Browser extension</h3>
        <p className="text-sm text-slate-500 mt-1 mb-4">
          Generate a pairing code and type it into the SafeBrowse extension. The extension never needs your password.
        </p>
        {pairError && <Alert kind="error">{pairError}</Alert>}
        {pair ? (
          <div className="rounded-xl bg-slate-50 border border-slate-200 p-4 text-center">
            <p className="text-3xl font-bold tracking-widest text-[#1e3a5f]">{pair.code}</p>
            <p className="text-xs text-slate-500 mt-1">One-time code, valid for {Math.floor(left / 60)}:{String(left % 60).padStart(2, "0")}</p>
          </div>
        ) : (
          <div className="max-w-xs"><SecondaryButton onClick={generate}>Generate pairing code</SecondaryButton></div>
        )}
        <h4 className="text-sm font-semibold text-slate-900 mt-6 mb-2">Connected extensions</h4>
        {devices.length === 0 ? (
          <p className="text-sm text-slate-500">None yet.</p>
        ) : (
          <ul className="divide-y divide-slate-100">
            {devices.map((d) => (
              <li key={d.id} className="py-2 flex items-center justify-between text-sm">
                <span className="text-slate-700">
                  {d.label ?? "Browser extension"}
                  <span className="text-slate-400"> · paired {new Date(d.paired_at).toLocaleDateString()}</span>
                </span>
                <button onClick={() => disconnect(d.id)} className="text-red-600 hover:underline text-xs">Disconnect</button>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}
