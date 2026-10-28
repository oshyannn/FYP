import StatusBadge from "../../../components/StatusBadge";
import { LEVEL_STYLE, detailSections, guidance, reasonsOf, scanTypeLabel, scoreText } from "../../../lib/analysis";
import type { ScanRecord } from "../../../lib/analysis";

interface Props {
  scan: ScanRecord;
  backLabel: string;
  onBack: () => void;
  onReport: () => void;
}

export default function DetailedAnalysis({ scan, backLabel, onBack, onReport }: Props) {
  const c = LEVEL_STYLE[scan.risk_level];
  const findings = reasonsOf(scan.analysis);

  return (
    <div className="max-w-2xl mx-auto space-y-5">
      <button onClick={onBack} className="text-slate-500 hover:text-slate-700 text-sm flex items-center gap-1">
        ← {backLabel}
      </button>

      <h2 className="text-xl font-bold text-slate-900">Detailed Security Analysis</h2>

      <div className="bg-white rounded-xl border border-slate-200 p-5">
        <div className="grid grid-cols-2 gap-4 text-sm">
          <div className="min-w-0">
            <p className="text-slate-500 text-xs mb-1">Scanned URL</p>
            <p className="font-mono text-slate-800 text-xs break-all">{scan.url}</p>
          </div>
          <div>
            <p className="text-slate-500 text-xs mb-1">Detection Date</p>
            <p className="text-slate-700">{new Date(scan.scanned_at).toLocaleString()}</p>
          </div>
          <div>
            <p className="text-slate-500 text-xs mb-1">Scan Type</p>
            <p className="text-slate-700">{scanTypeLabel(scan.scan_type)}</p>
          </div>
          <div>
            <p className="text-slate-500 text-xs mb-1">Risk Score</p>
            <p className={`font-bold ${c.text}`}>{scoreText(scan)}</p>
          </div>
          <div>
            <p className="text-slate-500 text-xs mb-1">Security Status</p>
            <StatusBadge level={scan.risk_level} />
          </div>
        </div>
      </div>

      {detailSections(scan).map((sec) => (
        <div key={sec.title} className="bg-white rounded-xl border border-slate-200 p-5">
          <h3 className="font-semibold text-slate-800 mb-3 flex items-center gap-2">
            <span>{sec.icon}</span>
            {sec.title}
          </h3>
          <div className="divide-y divide-slate-100">
            {sec.rows.map((row) => (
              <div key={row.label} className="flex justify-between gap-4 py-2.5 text-sm">
                <span className="text-slate-500">{row.label}</span>
                <span className="text-slate-800 font-medium text-right">{row.value}</span>
              </div>
            ))}
          </div>
        </div>
      ))}

      <div className="bg-white rounded-xl border border-slate-200 p-5">
        <h3 className="font-semibold text-slate-800 mb-3">4. Final Result</h3>
        <div className="flex items-center gap-4">
          <StatusBadge level={scan.risk_level} />
          <p className="text-sm text-slate-600">{guidance(scan.risk_level)}</p>
        </div>
        {findings.length > 0 && (
          <div className="mt-4 pt-4 border-t border-slate-100">
            <p className="text-xs font-medium text-slate-500 mb-2">All findings</p>
            <ul className="list-disc pl-5 space-y-1 text-sm text-slate-700">
              {findings.map((f, i) => (
                <li key={i}>{f}</li>
              ))}
            </ul>
          </div>
        )}
      </div>

      <button onClick={onReport} className="border border-slate-300 text-slate-700 px-5 py-2.5 rounded-lg text-sm font-medium hover:bg-slate-50 transition-colors">
        Report wrong detection
      </button>
    </div>
  );
}
