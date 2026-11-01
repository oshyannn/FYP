// One labelled percentage bar. Used by the scan result and the detailed analysis for the lists / APIs, AI 1, AI 2,
// the page-threat kinds and the final result. `value` is 0..100 (null = no value, shown as an empty grey bar).

interface Props {
  label: string;
  value: number | null;
  /** text on the right, e.g. "85%" or "70/100" */
  display: string;
  tone: { bar: string; text: string };
  note?: string;
  small?: boolean;
}

export default function RiskBar({ label, value, display, tone, note, small }: Props) {
  const width = value == null ? 0 : Math.max(0, Math.min(100, Math.round(value)));
  return (
    <div>
      <div className={`flex justify-between gap-3 ${small ? "text-xs" : "text-sm"} mb-1`}>
        <span className="text-slate-700 font-medium">{label}</span>
        <span className={`font-bold shrink-0 ${tone.text}`}>{display}</span>
      </div>
      <div className={`${small ? "h-1.5" : "h-2.5"} bg-slate-100 rounded-full overflow-hidden`}>
        <div className={`h-full ${tone.bar} rounded-full transition-all`} style={{ width: `${width}%` }} />
      </div>
      {note && <p className="text-xs text-slate-500 mt-1">{note}</p>}
    </div>
  );
}
