import { LEVEL_STYLE } from "../lib/analysis";
import type { Level } from "../lib/analysis";

const BADGE: Record<Level, string> = {
  safe: "bg-green-50 text-green-700 border border-green-200",
  suspicious: "bg-amber-50 text-amber-700 border border-amber-200",
  malicious: "bg-red-50 text-red-700 border border-red-200",
  unknown: "bg-slate-100 text-slate-600 border border-slate-200",
};

export default function StatusBadge({ level }: { level: Level }) {
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${BADGE[level]}`}>
      {LEVEL_STYLE[level].label}
    </span>
  );
}
