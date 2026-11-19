import { useCallback, useEffect, useRef, useState } from "react";
import { api, problem } from "../api";
import Badge from "./Badge";
import RiskBar from "./RiskBar";

interface DynamicEvidence {
  schema_version?: number;
  final_url?: string;
  navigation?: { redirect_count?: number; redirect_urls?: string[]; http_status?: number | null };
  network?: { request_count?: number; external_domains?: string[]; failed_request_count?: number; blocked_ssrf_count?: number };
  scripts?: { external_script_count?: number; inline_script_count?: number; script_urls?: string[] };
  dom?: {
    snapshot_captured?: boolean;
    rendered_html_bytes?: number;
    form_count?: number;
    password_field_count?: number;
    iframe_count?: number;
    external_form_actions?: string[];
  };
  behaviour?: {
    popup_count?: number;
    download_attempt_count?: number;
    download_filenames?: string[];
    console_error_count?: number;
    page_error_count?: number;
  };
  limitations?: string[];
}

interface Ai2Dynamic {
  model_version?: string;
  probability?: number;
  percent?: number;
  probability_calibrated?: number | null;
  calibrated_percent?: number | null;
  threshold?: number | null;
  flagged?: boolean | null;
  risk_tier?: "flagged" | "suspicious" | "low";
  signals?: string[];
  note?: string;
}

interface DynamicJob {
  id: string;
  status: "queued" | "running" | "completed" | "partial" | "failed" | "timed_out";
  evidence: DynamicEvidence;
  ai2_dynamic: Ai2Dynamic | null;
  error: string | null;
  duration_ms: number | null;
}

const STATUS_TONE: Record<DynamicJob["status"], "green" | "amber" | "red" | "blue" | "slate"> = {
  queued: "blue",
  running: "blue",
  completed: "green",
  partial: "amber",
  failed: "red",
  timed_out: "amber",
};

const BAR_TONE: Record<"flagged" | "suspicious" | "low", { bar: string; text: string }> = {
  flagged: { bar: "bg-red-500", text: "text-red-600" },
  suspicious: { bar: "bg-amber-500", text: "text-amber-600" },
  low: { bar: "bg-green-500", text: "text-green-600" },
};

type RiskTier = "flagged" | "suspicious" | "low";

function resolveAi2State(ai2d: Ai2Dynamic | null) {
  if (!ai2d) return null;
  const calPct =
    ai2d.calibrated_percent ??
    (ai2d.probability_calibrated != null ? Math.round(ai2d.probability_calibrated * 1000) / 10 : null);
  const displayPct = calPct ?? ai2d.percent ?? 0;
  const thrPct = ai2d.threshold != null ? Math.round(ai2d.threshold * 1000) / 10 : null;
  const isFlagged = ai2d.flagged === true || (calPct != null && thrPct != null && calPct >= thrPct);
  const tier: RiskTier = ai2d.risk_tier ?? (isFlagged ? "flagged" : displayPct >= 50 ? "suspicious" : "low");
  return { calPct, displayPct, thrPct, isFlagged, tier };
}

function buildFriendlySummary(
  job: DynamicJob,
  ev: DynamicEvidence,
  ai2State: ReturnType<typeof resolveAi2State>,
): { tone: "red" | "amber" | "green"; headline: string; body: string; points: string[] } {
  const redirects = ev.navigation?.redirect_count ?? 0;
  const forms = ev.dom?.form_count ?? 0;
  const passwords = ev.dom?.password_field_count ?? 0;
  const extForms = ev.dom?.external_form_actions ?? [];
  const downloads = ev.behaviour?.download_attempt_count ?? 0;
  const popups = ev.behaviour?.popup_count ?? 0;
  const blockedSsrf = ev.network?.blocked_ssrf_count ?? 0;
  const extDomains = ev.network?.external_domains?.length ?? 0;
  const extScripts = ev.scripts?.external_script_count ?? 0;

  const hasHighRiskBehaviour = downloads > 0 || extForms.length > 0 || blockedSsrf > 0;

  let tone: "red" | "amber" | "green" = "green";
  let headline = "No major warning signs found during the live visit";
  let body =
    "We safely opened this website in an isolated virtual browser and it behaved normally. Still, always double-check the web address before typing any personal details.";

  if (ai2State?.tier === "flagged") {
    tone = "red";
    headline = "High risk — avoid entering personal information on this page";
    body =
      "After loading the live webpage in a safe isolated browser, our AI detected strong signs of a phishing or deceptive site. Do not enter passwords, card numbers, or personal details here.";
  } else if (ai2State?.tier === "suspicious" || hasHighRiskBehaviour) {
    tone = "amber";
    headline = "Use caution — this page showed some unusual behaviour";
    body =
      ai2State?.tier === "suspicious"
        ? "Parts of the live webpage look suspicious, even though it did not cross our highest alert level. Verify the website address carefully before logging in or sharing any information."
        : "Although the page content itself did not trigger a high AI alert, we noticed unusual activity while it loaded. Review the highlights below before trusting this site.";
  } else if (job.status === "timed_out" || job.status === "partial") {
    tone = "amber";
    headline = "Partial result — the website did not finish loading in time";
    body =
      "The site was slow or blocked some automated loading, so this summary only reflects what happened before the time limit.";
  } else if (!ai2State) {
    tone = "amber";
    headline = "Live behaviour recorded (AI page check unavailable)";
    body =
      "We opened the page in a safe isolated browser, but there was not enough visible page content for our AI to score it. Review the activity below.";
  }

  const points: string[] = [];

  if (redirects === 0) {
    points.push("Stayed on the same web address without redirecting you elsewhere.");
  } else {
    points.push(
      `Automatically redirected ${redirects} ${redirects === 1 ? "time" : "times"}${ev.final_url ? ` before landing on ${ev.final_url}` : ""}.`,
    );
  }

  if (passwords > 0 && extForms.length > 0) {
    points.push(
      `Warning: Asks for a password (${passwords} field${passwords === 1 ? "" : "s"}) and sends form data to a different website (${extForms.join(", ")}). Legitimate login pages rarely send passwords to another domain.`,
    );
  } else if (passwords > 0) {
    points.push(
      `Contains a login or password input (${passwords} password field${passwords === 1 ? "" : "s"} across ${forms} form${forms === 1 ? "" : "s"}). Make sure you trust this website before signing in.`,
    );
  } else if (extForms.length > 0) {
    points.push(
      `Contains a form that submits information to a different website (${extForms.join(", ")}).`,
    );
  } else if (forms > 0) {
    points.push(`Contains ${forms} input form${forms === 1 ? "" : "s"}, with no password fields detected.`);
  } else {
    points.push("No login or data-entry forms were found on the page.");
  }

  if (downloads > 0) {
    points.push(
      `Warning: Tried to start ${downloads} automatic file download${downloads === 1 ? "" : "s"} as soon as the page opened.`,
    );
  }

  if (popups > 0) {
    points.push(`Tried to open ${popups} pop-up window${popups === 1 ? "" : "s"}.`);
  }

  if (blockedSsrf > 0) {
    points.push(
      `Warning: Tried to reach a private or local network address (${blockedSsrf} blocked attempt${blockedSsrf === 1 ? "" : "s"}), which normal public websites should not do.`,
    );
  }

  if (extDomains > 0 || extScripts > 0) {
    points.push(
      `Loaded resources from ${extDomains} external website${extDomains === 1 ? "" : "s"} and ran ${extScripts} external script${extScripts === 1 ? "" : "s"} (common on modern websites for images, fonts, or analytics).`,
    );
  }

  return { tone, headline, body, points };
}

export default function DynamicScanCard({
  scanId,
  onSessionEnd,
  onCompleted,
}: {
  scanId: string;
  onSessionEnd?: () => void;
  onCompleted?: () => void;
}) {
  const [job, setJob] = useState<DynamicJob | null>(null);
  const [loading, setLoading] = useState(true);
  const [starting, setStarting] = useState(false);
  const [err, setErr] = useState("");
  const wasActiveRef = useRef(false);

  const fetchStatus = useCallback(async () => {
    const res = await api.get(`/api/scans/${scanId}/dynamic`);
    setLoading(false);
    if (res.status === 401) {
      onSessionEnd?.();
      return;
    }
    if (res.status === 200) {
      const next = (res.data.dynamic as DynamicJob) ?? null;
      const isActive = next?.status === "queued" || next?.status === "running";
      if (wasActiveRef.current && !isActive && next && (next.status === "completed" || next.status === "partial")) {
        onCompleted?.();
      }
      wasActiveRef.current = isActive;
      setJob(next);
    }
  }, [scanId, onSessionEnd, onCompleted]);

  useEffect(() => {
    fetchStatus();
  }, [fetchStatus]);

  useEffect(() => {
    if (!job || (job.status !== "queued" && job.status !== "running")) return;
    const t = window.setInterval(fetchStatus, 2000);
    return () => window.clearInterval(t);
  }, [job, fetchStatus]);

  async function start() {
    if (starting) return;
    setStarting(true);
    setErr("");
    const res = await api.post(`/api/scans/${scanId}/dynamic`);
    setStarting(false);
    if (res.status === 401) {
      onSessionEnd?.();
      return;
    }
    if (res.status === 202) {
      setJob(res.data.dynamic as DynamicJob);
      return;
    }
    setErr(problem(res).message);
  }

  const ev = job?.evidence ?? {};
  const ai2d = job?.ai2_dynamic ?? null;
  const ai2State = resolveAi2State(ai2d);
  const active = job?.status === "queued" || job?.status === "running";

  const summaryToneCls = {
    red: "bg-red-50 border-red-200 text-red-900",
    amber: "bg-amber-50 border-amber-200 text-amber-900",
    green: "bg-green-50 border-green-200 text-green-900",
  };

  return (
    <div className="bg-white rounded-xl border border-slate-200 p-5 space-y-4">
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <div className="flex items-center gap-2">
            <h3 className="font-semibold text-slate-800">Dynamic Browser Analysis (Isolated Docker)</h3>
            {job && <Badge tone={STATUS_TONE[job.status]}>{job.status.replace("_", " ")}</Badge>}
          </div>
          <p className="text-xs text-slate-500 mt-0.5">
            Safely opens the website inside an isolated virtual browser to watch what it actually does (redirects, login forms, pop-ups, downloads) and checks the live page with AI.
          </p>
        </div>
        <button
          type="button"
          onClick={start}
          disabled={starting || active}
          className="shrink-0 bg-[#1e3a5f] text-white px-4 py-2 rounded-lg text-xs font-semibold hover:bg-[#162d4a] disabled:opacity-50 transition-colors"
        >
          {active ? "Scanning in Container…" : starting ? "Starting…" : job ? "Re-run Dynamic Scan" : "Run Deep Dynamic Scan"}
        </button>
      </div>

      {err && <p className="text-xs text-red-600 bg-red-50 border border-red-200 rounded-lg px-3 py-2">{err}</p>}
      {loading && <p className="text-xs text-slate-400">Checking dynamic scan status…</p>}

      {job && job.error && (
        <p className="text-xs text-red-700 bg-red-50 border border-red-200 rounded-lg px-3 py-2">
          {job.error}
        </p>
      )}

      {job && (job.status === "completed" || job.status === "partial" || job.status === "timed_out") && (() => {
        const summary = buildFriendlySummary(job, ev, ai2State);
        return (
        <div className="space-y-4">
          <div className={`rounded-lg border p-4 space-y-2 ${summaryToneCls[summary.tone]}`}>
            <div className="text-sm font-semibold">{summary.headline}</div>
            <p className="text-xs leading-relaxed opacity-90">{summary.body}</p>
            {summary.points.length > 0 && (
              <div className="pt-1">
                <div className="text-[11px] font-semibold uppercase tracking-wide opacity-75 mb-1">
                  What happened when we opened the page
                </div>
                <ul className="list-disc pl-5 text-xs space-y-1 opacity-90">
                  {summary.points.map((pt, i) => (
                    <li key={i} className="break-words">{pt}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>

          {ai2d && ai2State && (() => {
            const { calPct, displayPct, thrPct, tier } = ai2State;
            const badgeTone = tier === "flagged" ? "red" : tier === "suspicious" ? "amber" : "green";
            const badgeLabel = tier === "flagged" ? "Flagged" : tier === "suspicious" ? "Suspicious" : "Low risk";
            return (
              <div className="rounded-lg border border-slate-200 bg-slate-50 p-4 space-y-2">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-xs font-semibold text-slate-700">AI 2 — Live Page Risk Score</span>
                  <Badge tone={badgeTone}>{badgeLabel}</Badge>
                </div>
                <RiskBar
                  label={calPct != null ? "Calibrated phishing probability" : "Rendered-DOM phishing probability"}
                  value={displayPct}
                  display={`${displayPct}%`}
                  tone={BAR_TONE[tier]}
                  note={
                    thrPct != null
                      ? `Alert threshold: ${thrPct}%${ai2d.percent != null ? ` · Raw model: ${ai2d.percent}%` : ""} · ${ai2d.model_version ?? ""}`
                      : ai2d.model_version
                  }
                />
                {ai2d.signals && ai2d.signals.length > 0 && (
                  <div className="pt-1">
                    <div className="text-[11px] font-semibold text-slate-600 mb-0.5">Key signs detected by AI:</div>
                    <ul className="list-disc pl-5 text-xs text-slate-600 space-y-0.5">
                      {ai2d.signals.map((s, i) => (
                        <li key={i}>{s}</li>
                      ))}
                    </ul>
                  </div>
                )}
                <p className="text-[11px] text-slate-400">{ai2d.note}</p>
              </div>
            );
          })()}

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-center">
            <div className="rounded-lg border border-slate-200 p-3">
              <div className="text-lg font-bold text-slate-800">{ev.navigation?.redirect_count ?? 0}</div>
              <div className="text-[11px] text-slate-500">Redirects</div>
            </div>
            <div className="rounded-lg border border-slate-200 p-3">
              <div className="text-lg font-bold text-slate-800">{ev.network?.request_count ?? 0}</div>
              <div className="text-[11px] text-slate-500">Requests ({ev.network?.external_domains?.length ?? 0} ext. domains)</div>
            </div>
            <div className="rounded-lg border border-slate-200 p-3">
              <div className="text-lg font-bold text-slate-800">{ev.dom?.password_field_count ?? 0}</div>
              <div className="text-[11px] text-slate-500">Password Fields ({ev.dom?.form_count ?? 0} forms)</div>
            </div>
            <div className="rounded-lg border border-slate-200 p-3">
              <div className="text-lg font-bold text-slate-800">{ev.behaviour?.download_attempt_count ?? 0}</div>
              <div className="text-[11px] text-slate-500">Download Attempts</div>
            </div>
          </div>

          <div className="text-xs text-slate-600 space-y-1">
            {ev.final_url && (
              <p className="break-all">
                <span className="font-medium text-slate-700">Final URL: </span>
                <span className="font-mono">{ev.final_url}</span>
                {job.duration_ms != null && <span className="text-slate-400"> ({(job.duration_ms / 1000).toFixed(1)}s)</span>}
              </p>
            )}
            <p>
              <span className="font-medium text-slate-700">Scripts &amp; Frames: </span>
              {ev.scripts?.external_script_count ?? 0} external scripts, {ev.scripts?.inline_script_count ?? 0} inline scripts, {ev.dom?.iframe_count ?? 0} iframes, {ev.behaviour?.popup_count ?? 0} popups.
            </p>
            {(ev.dom?.external_form_actions?.length ?? 0) > 0 && (
              <p className="text-amber-700">
                <span className="font-medium">External form destinations: </span>
                {ev.dom!.external_form_actions!.join(", ")}
              </p>
            )}
            {(ev.network?.blocked_ssrf_count ?? 0) > 0 && (
              <p className="text-red-700">
                <span className="font-medium">Blocked internal/private requests: </span>
                {ev.network!.blocked_ssrf_count}
              </p>
            )}
          </div>

          {(ev.limitations?.length ?? 0) > 0 && (
            <div className="rounded-lg bg-amber-50 border border-amber-200 px-3 py-2 text-[11px] text-amber-800 space-y-0.5">
              <div className="font-semibold">Limitations</div>
              {ev.limitations!.map((l, i) => (
                <p key={i}>• {l}</p>
              ))}
            </div>
          )}
        </div>
        );
      })()}
    </div>
  );
}
