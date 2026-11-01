import type { ReactNode } from "react";
import RiskBar from "../../../components/RiskBar";
import StatusBadge from "../../../components/StatusBadge";
import {
  LEVEL_STYLE, breakdownBars, checkLabel, checkTone, detailSections, guidance, hasStructured, pctText, reasonsOf, riskTone,
  scanTypeLabel, scoreOrDash, scoreText, threatTone,
} from "../../../lib/analysis";
import type { AiResult, CheckItem, ScanRecord } from "../../../lib/analysis";

interface Props {
  scan: ScanRecord;
  backLabel: string;
  onBack: () => void;
  onReport: () => void;
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

function AiModelCard({ title, ai }: { title: string; ai?: AiResult }) {
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
    </Card>
  );
}

export default function DetailedAnalysis({ scan, backLabel, onBack, onReport }: Props) {
  const c = LEVEL_STYLE[scan.risk_level];
  const findings = reasonsOf(scan.analysis);
  const a = scan.analysis;
  const structured = hasStructured(a);
  const sections = detailSections(scan);
  const ai2 = a?.ai2;
  const cats = ai2?.categories ?? [];

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

          {/* 4. AI 2 with one percentage per kind of page threat */}
          <Card title="🤖 4. AI 2 · Page Content Model">
            {ai2 && (
              <>
                <RiskBar
                  label="Phishing probability"
                  value={ai2.percent}
                  display={ai2.state === "ok" ? pctText(ai2.percent) : ai2.state === "skipped" ? "Not run" : "No opinion"}
                  tone={riskTone(ai2.score)}
                  note={ai2.score == null ? undefined : `Risk score this model adds: ${ai2.score}/100`}
                />
                <p className="text-sm text-slate-600 mt-3">{ai2.description}</p>
              </>
            )}
            {cats.length > 0 && (
              <div className="mt-5 pt-4 border-t border-slate-100 space-y-4">
                <p className="text-xs font-medium text-slate-500">What the page scan looks for</p>
                {cats.map((k) => (
                  <div key={k.id}>
                    <RiskBar label={k.label} value={k.percent} display={`${k.percent}%`} tone={threatTone(k.level)} small />
                    <p className="text-xs text-slate-500 mt-1">{k.description}</p>
                  </div>
                ))}
                <p className="text-xs text-slate-400">
                  These percentages are rule-based: each one adds up the warning signs found in the page (forms, fields, title, scripts,
                  downloads). They explain the AI 2 result; they are not separate trained models.
                </p>
              </div>
            )}
            {(ai2?.signals?.length ?? 0) > 0 && (
              <div className="mt-4 pt-4 border-t border-slate-100">
                <p className="text-xs font-medium text-slate-500 mb-2">Warning signs seen on the page</p>
                <ul className="list-disc pl-5 space-y-1 text-sm text-slate-700">
                  {ai2!.signals!.map((s, i) => (
                    <li key={i}>{s}</li>
                  ))}
                </ul>
              </div>
            )}
          </Card>

          {/* 5. both AI models together */}
          {a?.ai_combined && (
            <Card title="🤖 5. AI Combined (AI 1 + AI 2)">
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
      <Card title={structured ? "6. Final Result: lists / APIs + AI" : "4. Final Result"}>
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
          <p className="text-sm text-slate-600">{guidance(scan.risk_level)}</p>
        </div>
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

      <button onClick={onReport} className="border border-slate-300 text-slate-700 px-5 py-2.5 rounded-lg text-sm font-medium hover:bg-slate-50 transition-colors">
        Report wrong detection
      </button>
    </div>
  );
}
