import type { Page } from "../types";
import StatusBadge from "../components/StatusBadge";

interface Props {
  navigate: (page: Page) => void;
  url?: string;
  status?: string;
  score?: number;
}

export default function DetailedAnalysis({ navigate, url = "https://example-site.com", status = "SUSPICIOUS", score = 62 }: Props) {
  const s = (status || "SUSPICIOUS").toUpperCase() as "SAFE" | "SUSPICIOUS" | "MALICIOUS";

  const urlInfo = [
    { label: "Domain", value: url.replace(/https?:\/\//, "").split("/")[0] },
    { label: "HTTPS", value: url.startsWith("https") ? "Yes ✓" : "No ✗" },
    { label: "URL Length", value: `${url.length} characters` },
    { label: "Suspicious Keywords", value: s === "SAFE" ? "None detected" : "login, account, verify" },
  ];

  const apiInfo = [
    { label: "Phishing Detection", value: s === "MALICIOUS" ? "Detected" : s === "SUSPICIOUS" ? "Possible" : "Not detected" },
    { label: "Malware Detection", value: s === "MALICIOUS" ? "Detected" : "Not detected" },
    { label: "Blacklist Status", value: s === "MALICIOUS" ? "Blacklisted" : s === "SUSPICIOUS" ? "Watchlisted" : "Not listed" },
  ];

  const aiInfo = [
    { label: "Prediction", value: s === "SAFE" ? "Legitimate" : s === "MALICIOUS" ? "Malicious" : "Suspicious" },
    { label: "Confidence", value: s === "SAFE" ? "94.2%" : s === "MALICIOUS" ? "97.8%" : "78.3%" },
  ];

  const scoreColor = s === "SAFE" ? "text-green-600" : s === "MALICIOUS" ? "text-red-600" : "text-amber-600";

  return (
    <div className="max-w-2xl mx-auto space-y-5">
      <div className="flex items-center gap-3">
        <button onClick={() => navigate("detection-history")} className="text-slate-500 hover:text-slate-700 text-sm flex items-center gap-1">
          ← Back to Detection History
        </button>
      </div>

      <h2 className="text-xl font-bold text-slate-900">Detailed Security Analysis</h2>

      {/* Overview */}
      <div className="bg-white rounded-xl border border-slate-200 p-5">
        <div className="grid grid-cols-2 gap-4 text-sm">
          <div>
            <p className="text-slate-500 text-xs mb-1">Scanned URL</p>
            <p className="font-mono text-slate-800 text-xs break-all">{url}</p>
          </div>
          <div>
            <p className="text-slate-500 text-xs mb-1">Detection Date</p>
            <p className="text-slate-700">31 Aug 2026, 10:32 AM</p>
          </div>
          <div>
            <p className="text-slate-500 text-xs mb-1">Scan Type</p>
            <p className="text-slate-700">Manual</p>
          </div>
          <div>
            <p className="text-slate-500 text-xs mb-1">Risk Score</p>
            <p className={`font-bold ${scoreColor}`}>{score}/100</p>
          </div>
          <div>
            <p className="text-slate-500 text-xs mb-1">Security Status</p>
            <StatusBadge status={s} />
          </div>
        </div>
      </div>

      {/* Sections */}
      {[
        { title: "1. URL Information", icon: "🔍", rows: urlInfo },
        { title: "2. Security API Verification", icon: "🛡️", rows: apiInfo },
        { title: "3. AI Detection", icon: "🤖", rows: aiInfo },
      ].map(sec => (
        <div key={sec.title} className="bg-white rounded-xl border border-slate-200 p-5">
          <h3 className="font-semibold text-slate-800 mb-3 flex items-center gap-2">
            <span>{sec.icon}</span>{sec.title}
          </h3>
          <div className="divide-y divide-slate-100">
            {sec.rows.map(row => (
              <div key={row.label} className="flex justify-between py-2.5 text-sm">
                <span className="text-slate-500">{row.label}</span>
                <span className="text-slate-800 font-medium">{row.value}</span>
              </div>
            ))}
          </div>
        </div>
      ))}

      {/* Final Result */}
      <div className="bg-white rounded-xl border border-slate-200 p-5">
        <h3 className="font-semibold text-slate-800 mb-3">4. Final Result</h3>
        <div className="flex items-center gap-4">
          <StatusBadge status={s} />
          <p className="text-sm text-slate-600">
            {s === "SAFE" && "This URL appears to be safe. No threats detected."}
            {s === "SUSPICIOUS" && "This URL shows suspicious characteristics. Exercise caution."}
            {s === "MALICIOUS" && "This URL is malicious. Access has been blocked for your safety."}
          </p>
        </div>
      </div>
    </div>
  );
}
