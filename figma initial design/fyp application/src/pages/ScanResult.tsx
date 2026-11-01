import type { Page } from "../types";

interface Props {
  navigate: (page: Page, url?: string, status?: string, score?: number) => void;
  url?: string;
  status?: string;
  score?: number;
}

export default function ScanResult({ navigate, url = "https://example-site.com", status = "SUSPICIOUS", score = 62 }: Props) {
  const s = status.toUpperCase();
  const colors = {
    SAFE: { bar: "bg-green-500", text: "text-green-600", bg: "bg-green-50", border: "border-green-200", label: "SAFE" },
    SUSPICIOUS: { bar: "bg-amber-500", text: "text-amber-600", bg: "bg-amber-50", border: "border-amber-200", label: "SUSPICIOUS" },
    MALICIOUS: { bar: "bg-red-500", text: "text-red-600", bg: "bg-red-50", border: "border-red-200", label: "MALICIOUS" },
  };
  const c = colors[s as keyof typeof colors] || colors.SUSPICIOUS;

  const cards = [
    { title: "URL Analysis", icon: "🔍", desc: s === "SAFE" ? "No suspicious URL characteristics detected." : s === "MALICIOUS" ? "Multiple malicious URL indicators found." : "Several suspicious URL characteristics detected." },
    { title: "Security API", icon: "🛡️", desc: s === "SAFE" ? "URL not found in threat databases." : "Potential threat information found." },
    { title: "AI Detection", icon: "🤖", desc: s === "SAFE" ? "Legitimate website" : s === "MALICIOUS" ? "Malicious website detected" : "Suspicious website" },
  ];

  return (
    <div className="max-w-2xl mx-auto space-y-6">
      <div className="flex items-center gap-3">
        <button onClick={() => navigate("url-scanner")} className="text-slate-500 hover:text-slate-700 text-sm flex items-center gap-1">
          ← Back
        </button>
        <h2 className="text-xl font-bold text-slate-900">URL Scan Result</h2>
      </div>

      {/* Main result card */}
      <div className={`bg-white rounded-xl border-2 ${c.border} p-6`}>
        <div className="flex items-start justify-between flex-wrap gap-4">
          <div>
            <p className="text-xs text-slate-500 mb-1">Scanned URL</p>
            <p className="text-sm font-mono text-slate-800 break-all">{url}</p>
          </div>
          <div className={`px-4 py-2 ${c.bg} rounded-lg`}>
            <span className={`text-sm font-bold ${c.text}`}>{c.label}</span>
          </div>
        </div>

        <div className="mt-5">
          <div className="flex justify-between text-xs text-slate-500 mb-1.5">
            <span>Risk Score</span>
            <span className={`font-bold text-sm ${c.text}`}>{score} / 100</span>
          </div>
          <div className="h-2.5 bg-slate-100 rounded-full overflow-hidden">
            <div className={`h-full ${c.bar} rounded-full transition-all`} style={{ width: `${score}%` }} />
          </div>
          <div className="flex justify-between text-xs text-slate-400 mt-1">
            <span>0 — Safe</span>
            <span>100 — Critical</span>
          </div>
        </div>
      </div>

      {/* Info cards */}
      <div className="grid grid-cols-3 gap-4">
        {cards.map(card => (
          <div key={card.title} className="bg-white rounded-xl border border-slate-200 p-4">
            <div className="text-xl mb-2">{card.icon}</div>
            <div className="text-sm font-semibold text-slate-800 mb-1">{card.title}</div>
            <div className="text-xs text-slate-500">{card.desc}</div>
          </div>
        ))}
      </div>

      {/* Actions */}
      <div className="flex flex-wrap gap-3">
        <button
          onClick={() => navigate("detailed-analysis", url, status, score)}
          className="bg-[#1e3a5f] text-white px-5 py-2.5 rounded-lg text-sm font-semibold hover:bg-[#162d4a] transition-colors"
        >
          View Detailed Analysis
        </button>
        <button
          onClick={() => navigate("url-scanner")}
          className="border border-slate-300 text-slate-700 px-5 py-2.5 rounded-lg text-sm font-medium hover:bg-slate-50 transition-colors"
        >
          Scan Another URL
        </button>
        <button
          onClick={() => navigate("user-dashboard")}
          className="border border-slate-300 text-slate-700 px-5 py-2.5 rounded-lg text-sm font-medium hover:bg-slate-50 transition-colors"
        >
          Back to Dashboard
        </button>
      </div>
    </div>
  );
}
