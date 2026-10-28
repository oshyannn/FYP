import { LEVEL_STYLE, summaryCards } from "../../../lib/analysis";
import type { ScanRecord } from "../../../lib/analysis";

interface Props {
  scan: ScanRecord;
  onBack: () => void;
  onDetails: () => void;
  onDashboard: () => void;
  onReport: () => void;
}

export default function ScanResult({ scan, onBack, onDetails, onDashboard, onReport }: Props) {
  const c = LEVEL_STYLE[scan.risk_level];
  const unknown = scan.risk_level === "unknown";
  const score = Math.round(scan.risk_score);

  return (
    <div className="max-w-2xl mx-auto space-y-6">
      <div className="flex items-center gap-3">
        <button onClick={onBack} className="text-slate-500 hover:text-slate-700 text-sm flex items-center gap-1">
          ← Back
        </button>
        <h2 className="text-xl font-bold text-slate-900">URL Scan Result</h2>
      </div>

      <div className={`bg-white rounded-xl border-2 ${c.border} p-6`}>
        <div className="flex items-start justify-between flex-wrap gap-4">
          <div className="min-w-0">
            <p className="text-xs text-slate-500 mb-1">Scanned URL</p>
            <p className="text-sm font-mono text-slate-800 break-all">{scan.url}</p>
          </div>
          <div className={`px-4 py-2 ${c.bg} rounded-lg`}>
            <span className={`text-sm font-bold ${c.text}`}>{c.label}</span>
          </div>
        </div>

        <div className="mt-5">
          <div className="flex justify-between text-xs text-slate-500 mb-1.5">
            <span>Risk Score</span>
            <span className={`font-bold text-sm ${c.text}`}>{unknown ? "Not available" : `${score} / 100`}</span>
          </div>
          <div className="h-2.5 bg-slate-100 rounded-full overflow-hidden">
            <div className={`h-full ${c.bar} rounded-full transition-all`} style={{ width: `${unknown ? 0 : score}%` }} />
          </div>
          <div className="flex justify-between text-xs text-slate-400 mt-1">
            <span>0 — Safe</span>
            <span>100 — Critical</span>
          </div>
          {unknown && (
            <p className="text-xs text-slate-500 mt-3">
              No source had data about this URL. That is not a guarantee that the site is safe.
            </p>
          )}
        </div>
      </div>

      <div className="grid grid-cols-3 gap-4">
        {summaryCards(scan).map((card) => (
          <div key={card.title} className="bg-white rounded-xl border border-slate-200 p-4">
            <div className="text-xl mb-2">{card.icon}</div>
            <div className="text-sm font-semibold text-slate-800 mb-1">{card.title}</div>
            <div className="text-xs text-slate-500">{card.text}</div>
          </div>
        ))}
      </div>

      <div className="flex flex-wrap gap-3">
        <button
          onClick={onDetails}
          className="bg-[#1e3a5f] text-white px-5 py-2.5 rounded-lg text-sm font-semibold hover:bg-[#162d4a] transition-colors"
        >
          View Detailed Analysis
        </button>
        <button
          onClick={onBack}
          className="border border-slate-300 text-slate-700 px-5 py-2.5 rounded-lg text-sm font-medium hover:bg-slate-50 transition-colors"
        >
          Scan Another URL
        </button>
        <button
          onClick={onDashboard}
          className="border border-slate-300 text-slate-700 px-5 py-2.5 rounded-lg text-sm font-medium hover:bg-slate-50 transition-colors"
        >
          Back to Dashboard
        </button>
        <button onClick={onReport} className="text-slate-500 px-2 py-2.5 text-sm font-medium hover:text-slate-800 hover:underline">
          Report wrong detection
        </button>
      </div>
    </div>
  );
}
