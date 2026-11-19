// Everything the popup shows about HOW a verdict was reached: every list / API, AI 1, AI 2 (with one percentage per kind of
// page threat), the AI combination and the final lists / APIs + AI combination. All data comes from the detector (detector.py);
// nothing is computed here except bar colours. Old backends do not send these fields: every block hides itself then.
import type { ReactNode } from "react";
import type { AiResult, CheckItem, ThreatCategory, Verdict } from "./types";

type Tone = { bar: string; text: string };

/** Colour for a 0..100 risk number (the detector's own limits: 30 = suspicious, 70 = malicious). */
const riskTone = (s: number | null | undefined): Tone =>
  s == null ? { bar: "bg-gray-300", text: "text-gray-500" }
    : s >= 70 ? { bar: "bg-red-500", text: "text-red-600" }
    : s >= 30 ? { bar: "bg-orange-500", text: "text-orange-500" }
    : { bar: "bg-green-500", text: "text-green-600" };

const threatTone = (l: ThreatCategory["level"]): Tone =>
  l === "high" ? { bar: "bg-red-500", text: "text-red-600" } : l === "medium" ? { bar: "bg-orange-500", text: "text-orange-500" } : { bar: "bg-green-500", text: "text-green-600" };

const pct = (p: number | null | undefined) => (p == null ? "No opinion" : `${Math.round(p)}%`);
const score100 = (s: number | null | undefined) => (s == null ? "—" : `${Math.round(s)}/100`);

export function MiniBar({ label, value, display, tone, note }: { label: string; value: number | null; display: string; tone: Tone; note?: string }) {
  const w = value == null ? 0 : Math.max(0, Math.min(100, Math.round(value)));
  return (
    <div>
      <div className="flex items-center justify-between gap-2 mb-0.5">
        <span className="text-[10px] font-medium text-gray-700">{label}</span>
        <span className={`text-[10px] font-bold font-mono shrink-0 ${tone.text}`}>{display}</span>
      </div>
      <div className="w-full h-1.5 bg-gray-200 rounded-full overflow-hidden">
        <div className={`h-full rounded-full ${tone.bar}`} style={{ width: `${w}%` }} />
      </div>
      {note && <div className="text-[9px] text-gray-400 mt-0.5 leading-snug">{note}</div>}
    </div>
  );
}

function Block({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="bg-white rounded-xl border border-gray-200 overflow-hidden mb-3">
      <div className="bg-[#0f2a4a] px-3 py-1.5 text-[10px] font-semibold text-white">{title}</div>
      <div className="p-3 space-y-2.5">{children}</div>
    </div>
  );
}

const badgeClass = (c: CheckItem) =>
  c.state === "match" ? (c.effect === "trust" ? "bg-green-50 text-green-700 border-green-200" : "bg-red-50 text-red-700 border-red-200")
    : c.state === "info" ? "bg-sky-50 text-sky-700 border-sky-200"
    : c.state === "clear" ? "bg-gray-50 text-gray-600 border-gray-200"
    : c.state === "unavailable" || c.state === "not_configured" ? "bg-orange-50 text-orange-600 border-orange-200"
    : "bg-gray-50 text-gray-400 border-gray-200";

const badgeText = (c: CheckItem) =>
  c.state === "match" ? (c.effect === "trust" ? "Trusted" : "Found")
    : c.state === "info" ? "Info"
    : c.state === "clear" ? "No record"
    : c.state === "unavailable" ? "Unavailable"
    : c.state === "not_configured" ? "Not configured"
    : c.state === "skipped" ? "Not needed"
    : "No opinion";

const GROUPS: { key: CheckItem["group"]; title: string }[] = [
  { key: "list", title: "Local lists" },
  { key: "api", title: "Security APIs" },
  { key: "rule", title: "Domain rules" },
];

export function SourcesBlock({ checks }: { checks?: CheckItem[] }) {
  if (!checks || !checks.length) return null;
  return (
    <Block title="Security API & List Verification">
      {GROUPS.map((g) => {
        const rows = checks.filter((c) => c.group === g.key);
        if (!rows.length) return null;
        return (
          <div key={g.key}>
            <div className="text-[9px] text-gray-400 uppercase tracking-wide mb-1">{g.title}</div>
            <div className="space-y-1.5">
              {rows.map((c) => (
                <div key={c.id}>
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-[11px] font-medium text-gray-800">{c.name}</span>
                    <span className={`text-[9px] font-semibold px-1.5 py-0.5 rounded-full border shrink-0 ${badgeClass(c)}`}>{badgeText(c)}</span>
                  </div>
                  <div className="text-[10px] text-gray-500 leading-snug">{c.detail}</div>
                </div>
              ))}
            </div>
          </div>
        );
      })}
    </Block>
  );
}

function AiBlock({ title, ai, children }: { title: string; ai?: AiResult; children?: ReactNode }) {
  if (!ai) return null;
  return (
    <Block title={title}>
      <MiniBar
        label="Phishing probability"
        value={ai.percent}
        display={ai.state === "ok" ? pct(ai.percent) : ai.state === "skipped" ? "Not run" : "No opinion"}
        tone={riskTone(ai.score)}
        note={ai.score == null ? undefined : `Risk score this model adds: ${ai.score}/100`}
      />
      <div className="text-[10px] text-gray-600 leading-relaxed">{ai.description}</div>
      {children}
    </Block>
  );
}

function Threats({ cats }: { cats: ThreatCategory[] }) {
  if (!cats.length) return null;
  return (
    <div className="border-t border-gray-100 pt-2.5 space-y-2.5">
      <div className="text-[9px] text-gray-400 uppercase tracking-wide">What the page scan looks for</div>
      {cats.map((k) => (
        <div key={k.id}>
          <MiniBar label={k.label} value={k.percent} display={`${k.percent}%`} tone={threatTone(k.level)} />
          <div className="text-[9px] text-gray-500 mt-0.5 leading-snug">{k.description}</div>
        </div>
      ))}
      <div className="text-[9px] text-gray-400 leading-snug">
        These percentages are rule-based: each adds up the warning signs found in the page. They explain the AI 2 result; they are not separate models.
      </div>
    </div>
  );
}

/** The honest summary: how sure we are, what speaks against / for the site, what could not be checked. */
export function AssessmentBlock({ v }: { v: Verdict }) {
  const a = v.final?.assessment;
  if (!a) return null;
  const list = (title: string, items: string[], cls: string) => items.length === 0 ? null : (
    <div>
      <div className={`text-[9px] font-semibold uppercase tracking-wide mb-0.5 ${cls}`}>{title}</div>
      <ul className="list-disc pl-4 space-y-0.5 text-[10px] text-gray-600">{items.map((t, i) => <li key={i}>{t}</li>)}</ul>
    </div>
  );
  return (
    <div className="space-y-2">
      <div className="text-[11px] font-semibold text-gray-800">{a.label} <span className="font-normal text-gray-400">({a.confidence} confidence)</span></div>
      <div className="text-[10px] text-gray-600 leading-relaxed">{a.summary}</div>
      {list("Against this site", a.concerns, "text-red-600")}
      {list("Speaks for this site / checked and clear", a.supporting, "text-green-700")}
      {list("Could not be checked", a.not_checked, "text-orange-600")}
    </div>
  );
}

/** Clear +/- score breakdown (Trusted / Untrusted / Risk + AI contribution), replacing confusing bars. */
export function Breakdown({ v }: { v: Verdict }) {
  const f = v.final;
  if (!f) return null;
  const checks = v.checks ?? [];
  const isTrusted =
    f.list_api.trusted === true ||
    checks.some((c) => c.group === "list" && c.state === "match" && c.effect === "trust");
  const trustDiscount = f.list_api.trust_discount ?? (isTrusted ? 25 : 0);
  const listRisk = f.list_api.score;
  const aiScore = f.ai.score;
  const bonus = f.bonus ?? 0;
  const finalScore = f.score ?? (v.status === "unknown" ? null : v.score);

  const listBadge =
    listRisk != null && listRisk >= 30
      ? { label: listRisk >= 70 ? "Malicious" : "Risk", cls: "bg-red-50 text-red-700 border-red-200", delta: `+${Math.round(listRisk)}`, dcls: "text-red-600" }
      : isTrusted
        ? { label: "Trusted", cls: "bg-green-50 text-green-700 border-green-200", delta: trustDiscount > 0 ? `-${trustDiscount}` : "Trusted", dcls: "text-green-600" }
        : listRisk != null && listRisk > 0
          ? { label: "Untrusted", cls: "bg-gray-100 text-gray-600 border-gray-200", delta: `+${Math.round(listRisk)}`, dcls: "text-gray-700" }
          : { label: "Untrusted", cls: "bg-gray-100 text-gray-600 border-gray-200", delta: trustDiscount > 0 ? `-${trustDiscount}` : "0", dcls: trustDiscount > 0 ? "text-green-600" : "text-gray-600" };

  const aiToneCls =
    aiScore == null
      ? "text-gray-400"
      : aiScore >= 30
        ? "text-red-600"
        : "text-green-600";

  const finalCls =
    v.status === "malicious"
      ? "text-red-600"
      : v.status === "suspicious"
        ? "text-orange-500"
        : v.status === "safe"
          ? "text-green-600"
          : "text-gray-500";

  return (
    <div className="divide-y divide-gray-100 border border-gray-200 rounded-lg overflow-hidden bg-white">
      <div className="px-2.5 py-2 flex items-center justify-between gap-2">
        <div className="flex items-center gap-1.5 min-w-0">
          <span className="text-[10px] font-medium text-gray-700">Lists / APIs</span>
          <span className={`text-[9px] font-semibold px-1.5 py-0.5 rounded-full border shrink-0 ${listBadge.cls}`}>{listBadge.label}</span>
        </div>
        <span className={`text-[11px] font-bold font-mono shrink-0 ${listBadge.dcls}`}>{listBadge.delta}</span>
      </div>
      <div className="px-2.5 py-2 flex items-center justify-between gap-2">
        <div className="flex items-center gap-1.5 min-w-0">
          <span className="text-[10px] font-medium text-gray-700">AI (30% AI1 + 70% AI2)</span>
        </div>
        <span className={`text-[11px] font-bold font-mono shrink-0 ${aiToneCls}`}>
          {aiScore == null ? "—" : `+${Math.round(aiScore)}`}
        </span>
      </div>
      {bonus > 0 && (
        <div className="px-2.5 py-2 flex items-center justify-between gap-2">
          <span className="text-[10px] font-medium text-gray-700">Agreement bonus</span>
          <span className="text-[11px] font-bold font-mono text-red-600 shrink-0">+{bonus}</span>
        </div>
      )}
      <div className="px-2.5 py-2 bg-gray-50 flex items-center justify-between gap-2">
        <span className="text-[10px] font-semibold text-gray-800">Final risk</span>
        <span className={`text-[11px] font-bold font-mono shrink-0 ${finalCls}`}>{score100(finalScore)}</span>
      </div>
    </div>
  );
}

/** All the blocks of the Details screen, in the order: sources, AI 1, AI 2, AI combined, final. */
export function AnalysisBlocks({ v }: { v: Verdict }) {
  if (!v.checks || !v.checks.length) return null;
  return (
    <>
      <SourcesBlock checks={v.checks} />
      <AiBlock title="AI 1 · URL model" ai={v.ai1} />
      <AiBlock title="AI 2 · Page content model" ai={v.ai2}>
        <Threats cats={v.ai2?.categories ?? []} />
        {(v.ai2?.signals?.length ?? 0) > 0 && (
          <div className="border-t border-gray-100 pt-2.5">
            <div className="text-[9px] text-gray-400 uppercase tracking-wide mb-1">Warning signs seen on the page</div>
            <ul className="list-disc pl-4 space-y-0.5 text-[10px] text-gray-600">
              {v.ai2!.signals!.map((s, i) => <li key={i}>{s}</li>)}
            </ul>
          </div>
        )}
      </AiBlock>
      {v.aiCombined && (
        <Block title="AI combined (AI 1 + AI 2)">
          <MiniBar label="Combined AI risk" value={v.aiCombined.score} display={score100(v.aiCombined.score)} tone={riskTone(v.aiCombined.score)} />
          <div className="text-[10px] text-gray-600 leading-relaxed">{v.aiCombined.description}</div>
        </Block>
      )}
      {v.final && (
        <Block title="Final result: lists / APIs + AI">
          <Breakdown v={v} />
          <div className="border-t border-gray-100 pt-2"><AssessmentBlock v={v} /></div>
          <div className="border-t border-gray-100 pt-2 space-y-1.5 text-[10px] text-gray-600 leading-relaxed">
            <div><span className="font-semibold text-gray-700">Lists / APIs: </span>{v.final.list_api.text}</div>
            <div><span className="font-semibold text-gray-700">AI models: </span>{v.final.ai.text}</div>
            {v.final.notes.length > 0 && <div><span className="font-semibold text-gray-700">Combined: </span>{v.final.notes.join(" ")}</div>}
            <div className="text-[9px] text-gray-400">{v.final.method}</div>
          </div>
        </Block>
      )}
    </>
  );
}
