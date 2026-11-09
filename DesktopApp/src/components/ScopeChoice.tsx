import type { MatchScope } from "../lib/threats";

// Optional choice for a front-page threat entry. "Whole site" is the normal behaviour and the default.
export default function ScopeChoice({ value, onChange }: { value: MatchScope; onChange: (v: MatchScope) => void }) {
  const opt = (v: MatchScope, title: string, text: string) => (
    <label className={`flex items-start gap-2.5 p-2.5 rounded-lg border cursor-pointer ${value === v ? "border-[#1e3a5f] bg-slate-50" : "border-slate-200"}`}>
      <input type="radio" name="scope" checked={value === v} onChange={() => onChange(v)} className="mt-1" />
      <span>
        <span className="block text-sm font-medium text-slate-800">{title}</span>
        <span className="block text-xs text-slate-500">{text}</span>
      </span>
    </label>
  );
  return (
    <div className="space-y-2 text-left my-3">
      <p className="text-xs font-medium text-slate-500">This is a front-page address. What should it block?</p>
      {opt("auto", "Whole site (default)", "The whole website and its subdomains are treated as a threat.")}
      {opt("exact", "This page only", "Only this exact address. Other pages of the site are checked normally. To block a whole site on purpose, use Detection Rules > Blacklist.")}
    </div>
  );
}
