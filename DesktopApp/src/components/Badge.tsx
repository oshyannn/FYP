import type { ReactNode } from "react";

export type Tone = "green" | "amber" | "red" | "orange" | "blue" | "slate";

const TONES: Record<Tone, string> = {
  green: "bg-green-50 text-green-700 border border-green-200",
  amber: "bg-amber-50 text-amber-700 border border-amber-200",
  red: "bg-red-50 text-red-700 border border-red-200",
  orange: "bg-orange-50 text-orange-700 border border-orange-200",
  blue: "bg-blue-50 text-blue-700 border border-blue-200",
  slate: "bg-slate-100 text-slate-600 border border-slate-200",
};

export default function Badge({ tone, children }: { tone: Tone; children: ReactNode }) {
  return <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${TONES[tone]}`}>{children}</span>;
}
