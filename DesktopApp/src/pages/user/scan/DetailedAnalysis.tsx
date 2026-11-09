import { useState } from "react";
import type { ReactNode } from "react";
import { api, problem } from "../../../api";
import RiskBar from "../../../components/RiskBar";
import StatusBadge from "../../../components/StatusBadge";
import { Alert } from "../../../components/ui";
import {
  CONFIDENCE_TEXT, LEVEL_STYLE, assessmentOf, breakdownBars, checkLabel, checkTone, detailSections, guidance, hasStructured, pctText, reasonsOf, riskTone,
  scanTypeLabel, scoreOrDash, scoreText,
} from "../../../lib/analysis";
import type { AiResult, CheckItem, ScanRecord } from "../../../lib/analysis";

interface Props {
  scan: ScanRecord;
  backLabel: string;
  onBack: () => void;
  onReport: () => void;
  onRescanned?: (scan: ScanRecord) => void;   // added: Re-scan shows the new result in place of this one
  onSessionEnd?: () => void;                  // added
}

function Card({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="bg-white rounded-xl border border-slate-200 p-5">
      <h3 className="font-semibold text-slate-800 mb-3">{title}</h3>
      {children}
    </div>
  );
}

const GROUPS: { key: CheckItem["group"]; title: string }[] = [
  { key: "list", title: "Local lists" },
  { key: "api", title: "Security APIs" },
  { key: "rule", title: "Domain rules" },
];

/** Every source the detector has, whether it found something or not. */
function SourceTable({ checks }: { checks: CheckItem[] }) {
  return (
    <div className="space-y-4">
      {GROUPS.map((g) => {
        const rows = checks.filter((c) => c.group === g.key);
        if (!rows.length) return null;
        return (
          <div key={g.key}>
            <p className="text-xs font-medium text-slate-500 mb-1">{g.title}</p>
            <div className="divide-y divide-slate-100">
              {rows.map((c) => (
                <div key={c.id} className="py-2.5 text-sm">
                  <div className="flex items-center justify-between gap-3">
                    <span className="text-slate-800 font-medium">{c.name}</span>
                    <span className={`text-xs font-semibold px-2 py-0.5 rounded-full border shrink-0 ${checkTone(c)}`}>{checkLabel(c)}</span>
                  </div>
                  <p className="text-xs text-slate-500 mt-0.5">{c.detail}</p>
                </div>
              ))}
            </div>
          </div>
        );
      })}
    </div>
  );
}

function AiModelCard({ title, ai, children }: { title: string; ai?: AiResult; children?: ReactNode }) {
  if (!ai) return null;
  const tone = riskTone(ai.score);
  return (
    <Card title={title}>
      <RiskBar
        label="Phishing probability"
        value={ai.percent}
        display={ai.state === "ok" ? pctText(ai.percent) : ai.state === "skipped" ? "Not run" : "No opinion"}
        tone={tone}
        note={ai.score == null ? undefined : `Risk score this model adds: ${ai.score}/100`}
      />
      <p className="text-sm text-slate-600 mt-3">{ai.description}</p>
      {children}
    </Card>
  );
}

// Rule-based page checks are NOT a model: no percentage bar (it looked like an AI result), just what was found and how strong.
function ruleStrength(percent: number): { label: string; cls: string } {
  if (percent >= 70) return { label: "Strong signs", cls: "bg-red-50 text-red-700 border-red-200" };
  if (percent >= 40) return { label: "Some signs", cls: "bg-amber-50 text-amber-700 border-amber-200" };
  if (percent > 0) return { label: "Weak signs", cls: "bg-slate-100 text-slate-700 border-slate-200" };
  return { label: "Nothing found", cls: "bg-green-50 text-green-700 border-green-200" };
}

export default function DetailedAnalysis({ scan, backLabel, onBack, onReport, onRescanned, onSessionEnd }: Props) {
  const [rescanning, setRescanning] = useState(false);
  const [error, setError] = useState("");
  const c = LEVEL_STYLE[scan.risk_level];
  const findings = reasonsOf(scan.analysis);
  const a = scan.analysis;
  const structured = hasStructured(a);
  const sections = detailSections(scan);
  const ai2 = a?.ai2;
  const cats = ai2?.categories ?? [];
  const asm = assessmentOf(scan);
  // sources that could not answer this time (a server that was not running, a lookup that failed, a page that could not be read)
  const incomplete = (a?.checks ?? []).filter(
    (k) => (k.state as string) === "unavailable" || ((k.id === "ai1" || k.id === "ai2") && (k.state as string) === "no_opinion"),
  );

  async function rescan() {
    if (rescanning) return;
    setRescanning(true);
    setError("");
    const res = await api.post("/api/scans", { url: scan.url, fresh: true });   // fresh: forget remembered answers for this address
    setRescanning(false);
    if (res.status === 401) return onSessionEnd?.();
    if (res.status === 201) onRescanned?.(res.data.scan as ScanRecord);
    else setError(res.status === 429 ? "Too many scans in a short time. Wait a moment and try again." : problem(res).message);
  }

  return (
    <div className="max-w-2xl mx-auto space-y-5">
      <button onClick={onBack} className="text-slate-500 hover:text-slate-700 text-sm flex items-center gap-1">
        ← {backLabel}
      </button>

      <div className="flex items-start justify-between gap-4">
        <h2 className="text-xl font-bold text-slate-900">Detailed Security Analysis</h2>
        {onRescanned && (
          <button
            onClick={rescan}
            disabled={rescanning}
            className="shrink-0 border border-slate-300 text-slate-700 px-4 py-2 rounded-lg text-sm font-medium hover:bg-slate-50 disabled:opacity-60"
          >
            {rescanning ? "Scanning…" : "Re-scan"}
          </button>
        )}
      </div>

      {error && <Alert kind="error">{error}</Alert>}
      {incomplete.length > 0 && (
        <Alert kind="info">
          This result is incomplete: {incomplete.map((k) => k.name).join(", ")} could not answer this time. That may be a lookup that failed, a page
          that could not be read, or a service that was not running. {onRescanned ? "Press Re-scan to ask again; the old answers are not reused." : "Scan the address again to ask again."}
        </Alert>
      )}

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

      {structured ? (
        <>
          {/* 1. URL information (same rows as before) */}
          <Card title={`${sections[0].icon} ${sections[0].title}`}>
            <div className="divide-y divide-slate-100">
              {sections[0].rows.map((row) => (
                <div key={row.label} className="flex justify-between gap-4 py-2.5 text-sm">
                  <span className="text-slate-500">{row.label}</span>
                  <span className="text-slate-800 font-medium text-right">{row.value}</span>
                </div>
              ))}
            </div>
          </Card>

          {/* 2. Every list / API / domain rule, also the ones that found nothing */}
          <Card title="🛡️ 2. Security API & List Verification">
            <SourceTable checks={a!.checks!} />
          </Card>

          {/* 3. AI 1 */}
          <AiModelCard title="🤖 3. AI 1 · URL Model" ai={a?.ai1} />

          {/* 4. AI 2: the model's probability only (the rule-based checks are their own card below) */}
          <AiModelCard title="🤖 4. AI 2 · Page Content Model" ai={ai2}>
            {ai2?.state === "ok" && (
              <p className="text-xs text-slate-400 mt-3">
                This percentage is the model's overall estimate from many features of the page. The model does not list reasons. The separate
                rule-based checks in section 5 are not part of it.
              </p>
            )}
          </AiModelCard>

          {/* 5. Rule-based page checks: a different kind of card on purpose (dashed, no AI bars) */}
          {cats.length > 0 && (
            <div className="bg-slate-50 rounded-xl border border-dashed border-slate-300 p-5">
              <div className="flex items-center justify-between gap-3 mb-1">
                <h3 className="font-semibold text-slate-800">🧰 5. Rule-based page checks</h3>
                <span className="text-[10px] font-semibold tracking-wide px-2 py-0.5 rounded border border-slate-300 text-slate-500 bg-white shrink-0">RULES · NOT AI</span>
              </div>
              <p className="text-xs text-slate-500 mb-3">
                Fixed rules that look for specific tricks in the page text. They are not a trained model and they are not the AI 2 probability.
                Scripts that only run after the page loads are not seen.
              </p>
              <div className="divide-y divide-slate-200">
                {cats.map((k) => {
                  const st = ruleStrength(k.percent);
                  return (
                    <div key={k.id} className="py-3">
                      <div className="flex items-center justify-between gap-3">
                        <span className="text-sm font-medium text-slate-800">{k.label}</span>
                        <span className={`text-xs font-semibold px-2 py-0.5 rounded-full border shrink-0 ${st.cls}`}>{st.label}</span>
                      </div>
                      <p className="text-xs text-slate-500 mt-1">{k.description}</p>
                    </div>
                  );
                })}
              </div>
              {(ai2?.signals?.length ?? 0) > 0 && (
                <div className="mt-3 pt-3 border-t border-slate-200">
                  <p className="text-xs font-medium text-slate-500 mb-2">Other things noticed on the page</p>
                  <ul className="list-disc pl-5 space-y-1 text-sm text-slate-700">
                    {ai2!.signals!.map((s, i) => (
                      <li key={i}>{s}</li>
                    ))}
                  </ul>
                </div>
              )}
              <p className="text-xs text-slate-400 mt-3">
                A sign-in page always has a password field, so "Fake login page: weak signs" on a real sign-in page is normal. It matters when the
                page is not on the website it claims to belong to.
              </p>
            </div>
          )}

          {/* 6. both AI models together */}
          {a?.ai_combined && (
            <Card title="🤖 6. AI Combined (AI 1 + AI 2)">
              <RiskBar
                label="Combined AI risk"
                value={a.ai_combined.score}
                display={scoreOrDash(a.ai_combined.score)}
                tone={riskTone(a.ai_combined.score)}
              />
              <p className="text-sm text-slate-600 mt-3">{a.ai_combined.description}</p>
            </Card>
          )}
        </>
      ) : (
        sections.map((sec, i) => (
          <Card key={sec.title} title={`${sec.icon} ${sec.title}`}>
            <div className="divide-y divide-slate-100">
              {sec.rows.map((row) => (
                <div key={row.label} className="flex justify-between gap-4 py-2.5 text-sm">
                  <span className="text-slate-500">{row.label}</span>
                  <span className="text-slate-800 font-medium text-right">{row.value}</span>
                </div>
              ))}
            </div>
            {i === sections.length - 1 && (
              <p className="text-xs text-slate-400 mt-3">
                This scan was saved before the detailed breakdown existed. Scan the URL again to see every source, both AI models and the
                combined result.
              </p>
            )}
          </Card>
        ))
      )}

      {/* final: lists / APIs + AI together */}
      <Card title={structured ? "7. Final Result: lists / APIs + AI" : "4. Final Result"}>
        {structured && (
          <div className="space-y-4 mb-5">
            {breakdownBars(scan).map((b) => (
              <RiskBar
                key={b.label}
                label={b.label}
                value={b.score}
                display={scoreOrDash(b.score)}
                tone={b.label === "Final risk" ? { bar: c.bar, text: c.text } : riskTone(b.score)}
                note={b.note}
              />
            ))}
          </div>
        )}
        <div className="flex items-center gap-4">
          <StatusBadge level={scan.risk_level} />
          <p className="text-sm text-slate-600">{asm ? asm.label : guidance(scan.risk_level)}</p>
        </div>
        {asm && (
          <div className="mt-4 space-y-3 text-sm">
            <p className="text-slate-700">
              {asm.summary} <span className="text-xs text-slate-400">({CONFIDENCE_TEXT[asm.confidence]})</span>
            </p>
            {asm.concerns.length > 0 && (
              <div>
                <p className="text-xs font-medium text-red-600 mb-1">Against this site</p>
                <ul className="list-disc pl-5 space-y-0.5 text-slate-700">{asm.concerns.map((t, i) => <li key={i}>{t}</li>)}</ul>
              </div>
            )}
            {asm.supporting.length > 0 && (
              <div>
                <p className="text-xs font-medium text-green-700 mb-1">Speaks for this site / checked and clear</p>
                <ul className="list-disc pl-5 space-y-0.5 text-slate-700">{asm.supporting.map((t, i) => <li key={i}>{t}</li>)}</ul>
              </div>
            )}
            {asm.not_checked.length > 0 && (
              <div>
                <p className="text-xs font-medium text-amber-700 mb-1">Could not be checked</p>
                <ul className="list-disc pl-5 space-y-0.5 text-slate-700">{asm.not_checked.map((t, i) => <li key={i}>{t}</li>)}</ul>
              </div>
            )}
          </div>
        )}
        {a?.final && (
          <div className="mt-4 pt-4 border-t border-slate-100 space-y-2">
            <p className="text-sm text-slate-700">
              <span className="font-medium">Lists / APIs: </span>
              {a.final.list_api.text}
            </p>
            <p className="text-sm text-slate-700">
              <span className="font-medium">AI models: </span>
              {a.final.ai.text}
            </p>
            {a.final.notes.length > 0 && (
              <p className="text-sm text-slate-700">
                <span className="font-medium">Combined: </span>
                {a.final.notes.join(" ")}
              </p>
            )}
            <p className="text-xs text-slate-400">{a.final.method}</p>
          </div>
        )}
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
      </Card>

      <div className="flex flex-wrap gap-3">
        <button onClick={onReport} className="border border-slate-300 text-slate-700 px-5 py-2.5 rounded-lg text-sm font-medium hover:bg-slate-50 transition-colors">
          Report wrong detection
        </button>
        {onRescanned && (
          <button onClick={rescan} disabled={rescanning} className="border border-slate-300 text-slate-700 px-5 py-2.5 rounded-lg text-sm font-medium hover:bg-slate-50 disabled:opacity-60 transition-colors">
            {rescanning ? "Scanning…" : "Re-scan this address"}
          </button>
        )}
      </div>
    </div>
  );
}
