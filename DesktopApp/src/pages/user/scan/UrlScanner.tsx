import { useState } from "react";
import { api, problem } from "../../../api";
import { Alert } from "../../../components/ui";
import type { ScanRecord } from "../../../lib/analysis";

interface Props {
  onScanned: (scan: ScanRecord) => void;
  onSessionEnd: () => void;
}

const INFO = [
  { icon: "🔍", title: "URL Analysis", desc: "Checks URL patterns and suspicious characteristics" },
  { icon: "🛡️", title: "Security APIs", desc: "Verifies against threat intelligence databases" },
  { icon: "🤖", title: "AI Detection", desc: "Machine learning model for malicious site detection" },
];

export default function UrlScanner({ onScanned, onSessionEnd }: Props) {
  const [url, setUrl] = useState("");
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState("");

  async function scan() {
    if (!url.trim() || scanning) return;
    setScanning(true);
    setError("");
    const res = await api.post("/api/scans", { url: url.trim() });
    setScanning(false);
    if (res.status === 401) {
      onSessionEnd();
      return;
    }
    if (res.status === 201) {
      onScanned(res.data.scan as ScanRecord);
      return;
    }
    const p = problem(res);
    setError(res.status === 429 ? "Too many scans in a short time. Wait a moment and try again." : (p.fields.url ?? p.message));
  }

  return (
    <div className="max-w-2xl mx-auto space-y-6">
      <div>
        <h2 className="text-xl font-bold text-slate-900">URL Security Scanner</h2>
        <p className="text-slate-500 text-sm mt-0.5">Manually check a website URL before visiting it.</p>
      </div>

      <div className="bg-white rounded-xl border border-slate-200 p-8">
        <div className="text-center mb-6">
          <div className="w-16 h-16 bg-blue-50 rounded-2xl flex items-center justify-center mx-auto mb-4">
            <svg width="32" height="32" viewBox="0 0 24 24" fill="none" aria-hidden="true">
              <path d="M12 2L4 6v6c0 5.25 3.5 10.15 8 11.5C16.5 22.15 20 17.25 20 12V6l-8-4z" fill="#1e3a5f" fillOpacity="0.15" />
              <path d="M12 2L4 6v6c0 5.25 3.5 10.15 8 11.5C16.5 22.15 20 17.25 20 12V6l-8-4z" stroke="#1e3a5f" strokeWidth="1.5" fill="none" />
              <circle cx="12" cy="12" r="3" fill="#1e3a5f" />
            </svg>
          </div>
          <h3 className="font-semibold text-slate-800">Enter URL to Scan</h3>
          <p className="text-slate-500 text-sm mt-1">We'll analyze the URL against our security database and AI models.</p>
        </div>

        {error && <Alert kind="error">{error}</Alert>}
        <label htmlFor="scan-url" className="sr-only">
          Website URL
        </label>
        <textarea
          id="scan-url"
          value={url}
          maxLength={2048}
          onChange={(e) => setUrl(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && !e.shiftKey) {
              e.preventDefault();
              scan();
            }
          }}
          placeholder="Paste website URL here, e.g. https://example.com"
          rows={3}
          className="w-full px-4 py-3 border border-slate-300 rounded-lg text-sm placeholder-slate-400 focus:outline-none focus:border-[#1e3a5f] focus:ring-2 focus:ring-[#1e3a5f]/10 transition-colors resize-none font-mono"
        />
        <button
          onClick={scan}
          disabled={scanning || !url.trim()}
          className="w-full mt-4 bg-[#1e3a5f] text-white py-3 rounded-lg text-sm font-semibold hover:bg-[#162d4a] disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
        >
          {scanning ? "Analyzing URL..." : "Scan URL"}
        </button>

        {scanning && (
          <div className="mt-6 flex items-center justify-center gap-3 text-slate-600" role="status">
            <div className="flex gap-1">
              {[0, 1, 2].map((i) => (
                <div key={i} className="w-2 h-2 bg-[#1e3a5f] rounded-full animate-bounce" style={{ animationDelay: `${i * 0.15}s` }} />
              ))}
            </div>
            <span className="text-sm">Analyzing URL...</span>
          </div>
        )}
      </div>

      <div className="grid grid-cols-3 gap-4">
        {INFO.map((c) => (
          <div key={c.title} className="bg-white rounded-xl border border-slate-200 p-4 text-center">
            <div className="text-2xl mb-2">{c.icon}</div>
            <div className="text-sm font-semibold text-slate-800 mb-1">{c.title}</div>
            <div className="text-xs text-slate-500">{c.desc}</div>
          </div>
        ))}
      </div>
    </div>
  );
}
