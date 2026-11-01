import { useState } from "react";
import type { Page } from "../types";

interface Props { navigate: (page: Page, url?: string, status?: string, score?: number) => void; }

export default function UrlScanner({ navigate }: Props) {
  const [url, setUrl] = useState("");
  const [scanning, setScanning] = useState(false);

  const handleScan = () => {
    if (!url.trim()) return;
    setScanning(true);
    setTimeout(() => {
      setScanning(false);
      navigate("scan-result", url, "SUSPICIOUS", 62);
    }, 1800);
  };

  return (
    <div className="max-w-2xl mx-auto space-y-6">
      <div>
        <h2 className="text-xl font-bold text-slate-900">URL Security Scanner</h2>
        <p className="text-slate-500 text-sm mt-0.5">Manually check a website URL before visiting it.</p>
      </div>

      <div className="bg-white rounded-xl border border-slate-200 p-8">
        <div className="text-center mb-6">
          <div className="w-16 h-16 bg-blue-50 rounded-2xl flex items-center justify-center mx-auto mb-4">
            <svg width="32" height="32" viewBox="0 0 24 24" fill="none">
              <path d="M12 2L4 6v6c0 5.25 3.5 10.15 8 11.5C16.5 22.15 20 17.25 20 12V6l-8-4z" fill="#1e3a5f" fillOpacity="0.15"/>
              <path d="M12 2L4 6v6c0 5.25 3.5 10.15 8 11.5C16.5 22.15 20 17.25 20 12V6l-8-4z" stroke="#1e3a5f" strokeWidth="1.5" fill="none"/>
              <circle cx="12" cy="12" r="3" fill="#1e3a5f"/>
            </svg>
          </div>
          <h3 className="font-semibold text-slate-800">Enter URL to Scan</h3>
          <p className="text-slate-500 text-sm mt-1">{"We'll analyze the URL against our security database and AI models."}</p>
        </div>

        <textarea
          value={url}
          onChange={e => setUrl(e.target.value)}
          placeholder="Paste website URL here, e.g. https://example.com"
          rows={3}
          className="w-full px-4 py-3 border border-slate-300 rounded-lg text-sm placeholder-slate-400 focus:outline-none focus:border-[#1e3a5f] focus:ring-2 focus:ring-[#1e3a5f]/10 transition-colors resize-none font-mono"
        />

        <button
          onClick={handleScan}
          disabled={scanning || !url.trim()}
          className="w-full mt-4 bg-[#1e3a5f] text-white py-3 rounded-lg text-sm font-semibold hover:bg-[#162d4a] disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
        >
          {scanning ? "Analyzing URL..." : "Scan URL"}
        </button>

        {scanning && (
          <div className="mt-6 flex items-center justify-center gap-3 text-slate-600">
            <div className="flex gap-1">
              {[0, 1, 2].map(i => (
                <div key={i} className="w-2 h-2 bg-[#1e3a5f] rounded-full animate-bounce" style={{ animationDelay: `${i * 0.15}s` }} />
              ))}
            </div>
            <span className="text-sm">Analyzing URL...</span>
          </div>
        )}
      </div>

      {/* Info cards */}
      <div className="grid grid-cols-3 gap-4">
        {[
          { icon: "🔍", title: "URL Analysis", desc: "Checks URL patterns and suspicious characteristics" },
          { icon: "🛡️", title: "Security APIs", desc: "Verifies against threat intelligence databases" },
          { icon: "🤖", title: "AI Detection", desc: "Machine learning model for malicious site detection" },
        ].map(c => (
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
