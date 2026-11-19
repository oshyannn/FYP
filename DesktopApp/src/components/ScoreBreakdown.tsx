import { LEVEL_STYLE, scoreBreakdown, scoreOrDash } from "../lib/analysis";
import type { ScanRecord } from "../lib/analysis";

const BADGE_CLS = {
  trust: "bg-green-50 text-green-700 border-green-200",
  risk: "bg-red-50 text-red-700 border-red-200",
  neutral: "bg-slate-100 text-slate-600 border-slate-200",
};

const DELTA_CLS = {
  trust: "text-green-600",
  risk: "text-red-600",
  neutral: "text-slate-600",
};

export default function ScoreBreakdown({ scan }: { scan: ScanRecord }) {
  const rows = scoreBreakdown(scan);
  if (!rows.length) return null;
  const finalScore = scan.analysis?.final?.score ?? (scan.risk_level === "unknown" ? null : scan.risk_score);
  const c = LEVEL_STYLE[scan.risk_level];

  return (
    <div className="divide-y divide-slate-100 border border-slate-200 rounded-xl overflow-hidden bg-white">
      {rows.map((r) => (
        <div key={r.label} className="px-4 py-3 flex items-center justify-between gap-4">
          <div className="min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-sm font-medium text-slate-800">{r.label}</span>
              <span className={`text-[11px] font-semibold px-2 py-0.5 rounded-full border ${BADGE_CLS[r.tone]}`}>
                {r.badge}
              </span>
            </div>
            <p className="text-xs text-slate-500 mt-0.5">{r.note}</p>
          </div>
          <span className={`text-sm font-bold font-mono shrink-0 ${DELTA_CLS[r.tone]}`}>{r.deltaText}</span>
        </div>
      ))}
      <div className="px-4 py-3 bg-slate-50 flex items-center justify-between gap-4">
        <div>
          <span className="text-sm font-semibold text-slate-800">Final Risk Score</span>
          <p className="text-xs text-slate-500">0–29 Safe · 30–69 Suspicious · 70–100 Malicious</p>
        </div>
        <span className={`text-base font-bold font-mono shrink-0 ${c.text}`}>
          {scoreOrDash(finalScore)}
        </span>
      </div>
    </div>
  );
}
