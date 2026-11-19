// The ONE place that turns the detector's result into what the screens show. If the detector changes (new signals,
// new fields), this is the only file that may need a change: every screen reads through these functions.

export type Level = "safe" | "suspicious" | "malicious" | "unknown";
export type ScanType = "auto" | "manual" | "redirect";

/** One source the detector asked (list, PhishTank, Safe Browsing, look-alike, domain age, AI 1, AI 2). */
export interface CheckItem {
  id: string;
  name: string;
  group: "list" | "api" | "rule" | "ai";
  state: "match" | "clear" | "info" | "unavailable" | "not_configured" | "skipped" | "no_opinion";
  detail: string;
  score: number | null;
  effect: "risk" | "trust" | "none";
}
/** One kind of page threat found by AI 2 (fake login, fake bank / payment, hidden download ...). */
export interface ThreatCategory {
  id: string;
  label: string;
  percent: number;
  level: "low" | "medium" | "high";
  triggered: boolean;
  description: string;
  evidence: string[];
}
export interface AiResult {
  name: string;
  state: "ok" | "no_opinion" | "skipped";
  percent: number | null; // phishing probability in percent (AI 1, AI 2)
  score: number | null; // risk score 0..100 that this model contributes
  level: "none" | "low" | "elevated" | "high";
  description: string;
  categories?: ThreatCategory[];
  signals?: string[];
  download?: { kind: string | null; file: string } | null;
}
export interface Assessment {
  label: string;
  confidence: "high" | "medium" | "low";
  summary: string;
  supporting: string[];
  concerns: string[];
  not_checked: string[];
}
export interface FinalResult {
  assessment?: Assessment;
  status: string;
  score: number | null;
  list_api: { score: number | null; text: string; trusted?: boolean; trust_discount?: number };
  ai: { score: number | null; text: string };
  bonus?: number;
  notes: string[];
  method: string;
  summary: string;
}

export interface Analysis {
  status?: string;
  checks?: CheckItem[];
  ai1?: AiResult;
  ai2?: AiResult;
  ai_combined?: AiResult;
  final?: FinalResult;
  risk_score?: number;
  has_data?: boolean;
  source?: string;
  reasons?: string[];
  match_scope?: "exact" | "domain" | null;
  phish_id?: string | number | null;
  ml_probability?: number; // optional: used when the detector provides it, else read from `reasons`
  [key: string]: unknown;
}

export interface ScanRecord {
  id: string;
  url: string;
  domain: string;
  scan_type: ScanType;
  user_action: string;
  scanned_at: string;
  risk_level: Level;
  risk_score: number;
  analysis?: Analysis;
  threat_type?: string | null;
  list_status?: string | null;
  detection_count?: number | null;
  is_saved?: boolean;
}

export const LEVEL_STYLE: Record<Level, { bar: string; text: string; bg: string; border: string; label: string }> = {
  safe: { bar: "bg-green-500", text: "text-green-600", bg: "bg-green-50", border: "border-green-200", label: "SAFE" },
  suspicious: { bar: "bg-amber-500", text: "text-amber-600", bg: "bg-amber-50", border: "border-amber-200", label: "SUSPICIOUS" },
  malicious: { bar: "bg-red-500", text: "text-red-600", bg: "bg-red-50", border: "border-red-200", label: "MALICIOUS" },
  unknown: { bar: "bg-slate-400", text: "text-slate-600", bg: "bg-slate-100", border: "border-slate-300", label: "UNKNOWN" },
};

export function scanTypeLabel(t: ScanType | string): string {
  return t === "auto" ? "Automatic" : t === "manual" ? "Manual" : t === "redirect" ? "Redirect" : String(t);
}

export function scoreText(rec: Pick<ScanRecord, "risk_level" | "risk_score" | "analysis">): string {
  const finalScore = rec.analysis?.final?.score;
  if (rec.risk_level === "unknown" && finalScore == null) return "—";
  return `${Math.round(finalScore ?? rec.risk_score)}/100`;
}

export function reasonsOf(a?: Analysis): string[] {
  return Array.isArray(a?.reasons) ? (a!.reasons as unknown[]).filter((r): r is string => typeof r === "string") : [];
}

/** Phishing probability in percent, or null if the model gave no opinion. */
export function mlProbability(a?: Analysis): number | null {
  if (a?.ai1 && a.ai1.state !== "skipped") return a.ai1.percent ?? null;
  if (typeof a?.ml_probability === "number") {
    const p = a.ml_probability;
    return Math.round(p <= 1 ? p * 100 : p);
  }
  for (const r of reasonsOf(a)) {
    const m = /phishing probability (\d{1,3})%/i.exec(r);
    if (m) return Number(m[1]);
  }
  return null;
}

export function protocolOf(url: string): "https" | "http" | "none" {
  const u = url.trim().toLowerCase();
  return u.startsWith("https://") ? "https" : u.startsWith("http://") ? "http" : "none";
}

const unavailable = (a?: Analysis) => reasonsOf(a).some((r) => /phishtank unavailable/i.test(r));

export function phishtankText(a?: Analysis): string {
  if (a?.phish_id != null) return `Match found (${a.match_scope === "domain" ? "domain level" : "exact page"}, ID ${a.phish_id})`;
  if (unavailable(a)) return "Unavailable (lookup failed)";
  if (a?.source === "blacklist" || a?.source === "whitelist") return "Not needed (decided by a local list)";
  return "No match";
}

export function listText(a?: Analysis): string {
  return a?.source === "blacklist" ? "Blacklisted" : a?.source === "whitelist" ? "Trusted domain" : "Not listed";
}

const SOURCES: Record<string, string> = {
  blacklist: "Blacklist / threat feed",
  whitelist: "Trusted list",
  phishtank: "PhishTank",
  model: "AI model",
  "phishtank+model": "PhishTank and AI model",
  "shared-host": "Public hosting platform rule",
  none: "No source had data",
};
export function sourceText(source?: string): string {
  return source ? (SOURCES[source] ?? source) : "—";
}

export function apiVerdict(a?: Analysis): string {
  if (a?.source === "blacklist") return "Listed in the threat blacklist.";
  if (a?.phish_id != null) {
    return a.match_scope === "domain" ? "A PhishTank record exists for this domain." : "This exact page matches a PhishTank record.";
  }
  if (unavailable(a)) return "PhishTank could not be reached, so it was not checked.";
  if (a?.source === "whitelist") return "Known trusted domain.";
  return "Not found in the threat databases.";
}

export function guidance(level: Level): string {
  return {
    safe: "This URL appears to be safe. No threats detected.",
    suspicious: "This URL shows suspicious characteristics. Exercise caution.",
    malicious: "This URL is malicious. Do not open it.",
    unknown: "No warning signs were found, but nothing vouches for this site either, so it is not confirmed safe. See the details for what was and was not checked.",
  }[level];
}

export interface Card { title: string; icon: string; text: string }

function structuredCards(rec: ScanRecord): Card[] {
  const a = rec.analysis!;
  const proto = protocolOf(rec.url);
  const checks = a.checks ?? [];
  const used = checks.filter((c) => c.group !== "ai" && (c.state === "match" || c.state === "clear")).length;
  const hits = checks.filter((c) => c.group !== "ai" && c.state === "match" && c.effect === "risk");
  const total = checks.filter((c) => c.group !== "ai").length;
  const ai1 = a.ai1;
  const ai2 = a.ai2;
  return [
    {
      title: "URL Analysis",
      icon: "🔍",
      text: proto === "https" ? "Uses a secure connection (HTTPS)." : proto === "http" ? "No HTTPS: the connection is not encrypted." : "The address was entered without http:// or https://.",
    },
    {
      title: "Lists & APIs",
      icon: "🛡️",
      text: hits.length ? `Reported by ${hits.map((h) => h.name).join(", ")}.` : `${used} of ${total} sources checked: no record found.`,
    },
    {
      title: "AI Detection",
      icon: "🤖",
      text: `AI 1 (URL) ${pctText(ai1?.percent)} · AI 2 (page) ${pctText(ai2?.percent)} · combined ${scoreOrDash(a.ai_combined?.score)}.`,
    },
  ];
}

export function summaryCards(rec: ScanRecord): Card[] {
  if (hasStructured(rec.analysis)) return structuredCards(rec);
  const a = rec.analysis;
  const proto = protocolOf(rec.url);
  const ml = mlProbability(a);
  return [
    {
      title: "URL Analysis",
      icon: "🔍",
      text: proto === "https" ? "Uses a secure connection (HTTPS)." : proto === "http" ? "No HTTPS: the connection is not encrypted." : "The address was entered without http:// or https://.",
    },
    { title: "Security API", icon: "🛡️", text: apiVerdict(a) },
    { title: "AI Detection", icon: "🤖", text: ml === null ? "The model gave no opinion." : `Phishing probability ${ml}%.` },
  ];
}

export interface Section { title: string; icon: string; rows: { label: string; value: string }[] }

export function detailSections(rec: ScanRecord): Section[] {
  const a = rec.analysis;
  const proto = protocolOf(rec.url);
  const ml = mlProbability(a);
  return [
    {
      title: "1. URL Information",
      icon: "🔍",
      rows: [
        { label: "Domain", value: rec.domain },
        { label: "Protocol", value: proto === "https" ? "HTTPS ✓" : proto === "http" ? "HTTP ✗ (not encrypted)" : "Not specified" },
        { label: "URL length", value: `${rec.url.length} characters` },
        { label: "Scan type", value: scanTypeLabel(rec.scan_type) },
      ],
    },
    {
      title: "2. Security API Verification",
      icon: "🛡️",
      rows: [
        { label: "PhishTank", value: phishtankText(a) },
        { label: "Blacklist / trusted list", value: listText(a) },
        { label: "Decided by", value: sourceText(a?.source) },
      ],
    },
    {
      title: "3. AI Detection",
      icon: "🤖",
      rows: [{ label: "Phishing probability", value: ml === null ? "No opinion from the model" : `${ml}%` }],
    },
  ];
}


// ---- structured detector output (new records). Older saved scans do not have these fields: every helper falls back. ----

export function hasStructured(a?: Analysis): boolean {
  return Array.isArray(a?.checks) && a!.checks!.length > 0;
}

export const STATE_LABEL: Record<CheckItem["state"], string> = {
  match: "Found",
  clear: "No record",
  info: "Info",
  unavailable: "Unavailable",
  not_configured: "Not configured",
  skipped: "Not needed",
  no_opinion: "No opinion",
};

/** Tailwind classes for a source's badge: red = evidence against the site, green = trusted list, grey = nothing / not used. */
export function checkTone(c: CheckItem): string {
  if (c.state === "match") return c.effect === "trust" ? "bg-green-50 text-green-700 border-green-200" : "bg-red-50 text-red-700 border-red-200";
  if (c.state === "info") return "bg-sky-50 text-sky-700 border-sky-200";
  if (c.state === "clear") return "bg-slate-50 text-slate-600 border-slate-200";
  if (c.state === "unavailable" || c.state === "not_configured") return "bg-amber-50 text-amber-700 border-amber-200";
  return "bg-slate-50 text-slate-400 border-slate-200";
}

export function checkLabel(c: CheckItem): string {
  return c.state === "match" && c.effect === "trust" ? "Trusted" : STATE_LABEL[c.state];
}

/** Bar colour for a 0..100 risk number (same 30 / 70 limits the detector uses). null = no value. */
export function riskTone(score: number | null | undefined): { bar: string; text: string } {
  if (score == null) return { bar: "bg-slate-300", text: "text-slate-500" };
  if (score >= 70) return { bar: "bg-red-500", text: "text-red-600" };
  if (score >= 30) return { bar: "bg-amber-500", text: "text-amber-600" };
  return { bar: "bg-green-500", text: "text-green-600" };
}

/** Bar colour for a page-threat percentage (these use their own 20 / 50 limits, see page_threats.py). */
export function threatTone(level: ThreatCategory["level"]): { bar: string; text: string } {
  return level === "high" ? { bar: "bg-red-500", text: "text-red-600" } : level === "medium" ? { bar: "bg-amber-500", text: "text-amber-600" } : { bar: "bg-green-500", text: "text-green-600" };
}

export const pctText = (p: number | null | undefined): string => (p == null ? "No opinion" : `${Math.round(p)}%`);
export const scoreOrDash = (s: number | null | undefined): string => (s == null ? "—" : `${Math.round(s)}/100`);

export interface ScoreContribution {
  label: string;
  badge: string;
  tone: "trust" | "risk" | "neutral";
  deltaText: string;
  note: string;
}

/** Clear +/- score breakdown (Trusted / Untrusted / Risk + AI contribution), replacing confusing bar charts. */
export function scoreBreakdown(rec: ScanRecord): ScoreContribution[] {
  const f = rec.analysis?.final;
  if (!f) return [];
  const checks = rec.analysis?.checks ?? [];
  const isTrusted =
    f.list_api.trusted === true ||
    checks.some((c) => c.group === "list" && c.state === "match" && c.effect === "trust");
  const trustDiscount = f.list_api.trust_discount ?? (isTrusted ? 25 : 0);
  const listRisk = f.list_api.score;
  const aiScore = f.ai.score;
  const bonus = f.bonus ?? 0;

  const rows: ScoreContribution[] = [];

  if (listRisk != null && listRisk >= 30) {
    rows.push({
      label: "Lists / APIs / Rules",
      badge: listRisk >= 70 ? "Malicious Match" : "Risk Found",
      tone: "risk",
      deltaText: `+${Math.round(listRisk)}`,
      note: "Risk signal from threat lists, APIs, or domain rules (45% weight unless hard-blocked)",
    });
  } else if (isTrusted) {
    rows.push({
      label: "Lists / APIs / Rules",
      badge: "Trusted",
      tone: "trust",
      deltaText: trustDiscount > 0 ? `-${trustDiscount}` : "Trusted",
      note: trustDiscount > 0 ? "Domain is on a trusted list (reduces risk score)" : "Domain is on a trusted list",
    });
  } else if (listRisk != null && listRisk > 0) {
    rows.push({
      label: "Lists / APIs / Rules",
      badge: "Untrusted",
      tone: "neutral",
      deltaText: `+${Math.round(listRisk)}`,
      note: "Not on a trusted list; minor rule signal applied",
    });
  } else {
    rows.push({
      label: "Lists / APIs / Rules",
      badge: "Untrusted",
      tone: "neutral",
      deltaText: trustDiscount > 0 ? `-${trustDiscount}` : "0",
      note: trustDiscount > 0 ? "Not on a trusted list, but established domain age reduces risk" : "Not on any trusted or threat list",
    });
  }

  if (aiScore != null) {
    rows.push({
      label: "AI Models (30% AI 1 + 70% AI 2)",
      badge: aiScore >= 70 ? "High Risk" : aiScore >= 30 ? "Suspicious" : "Low Risk",
      tone: aiScore >= 30 ? "risk" : "trust",
      deltaText: `+${Math.round(aiScore)}`,
      note: listRisk != null && listRisk > 0 ? "Combined AI score (55% weight)" : "Combined AI score",
    });
  } else {
    rows.push({
      label: "AI Models (30% AI 1 + 70% AI 2)",
      badge: "No Opinion",
      tone: "neutral",
      deltaText: "—",
      note: "AI models were skipped or could not score this page",
    });
  }

  if (bonus > 0) {
    rows.push({
      label: "Agreement Bonus",
      badge: "2+ Signals",
      tone: "risk",
      deltaText: `+${bonus}`,
      note: "Added because both AI models and Reputation/Rules flagged this site",
    });
  }

  return rows;
}

export interface BreakdownBar { label: string; score: number | null; note: string }

/** The three numbers that explain the verdict: lists / APIs, AI models, and the final result. */
export function breakdownBars(rec: ScanRecord): BreakdownBar[] {
  const f = rec.analysis?.final;
  if (!f) return [];
  const finalScore = f.score ?? (rec.risk_level === "unknown" ? null : rec.risk_score);
  return [
    { label: "Lists / APIs", score: f.list_api.score, note: f.list_api.score == null ? "No evidence from lists or APIs" : "Highest score from lists, PhishTank, Google Safe Browsing and domain rules" },
    { label: "AI models (AI 1 + AI 2)", score: f.ai.score, note: f.ai.score == null ? "No AI result" : "Both AI models combined" },
    { label: "Final risk", score: finalScore, note: "Lists / APIs and AI together" },
  ];
}

/** The honest answer from the detector (label, how sure, what speaks for / against, what could not be checked). */
export function assessmentOf(scan: ScanRecord): Assessment | null {
  return scan.analysis?.final?.assessment ?? null;
}

export const CONFIDENCE_TEXT: Record<Assessment["confidence"], string> = { high: "High confidence", medium: "Medium confidence", low: "Low confidence" };
