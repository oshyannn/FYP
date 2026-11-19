import { useCallback, useEffect, useState } from "react";
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
  threshold?: number | null;
  flagged?: boolean | null;
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

export default function DynamicScanCard({ scanId, onSessionEnd }: { scanId: string; onSessionEnd?: () => void }) {
  const [job, setJob] = useState<DynamicJob | null>(null);
  const [loading, setLoading] = useState(true);
  const [starting, setStarting] = useState(false);
  const [err, setErr] = useState("");

  const fetchStatus = useCallback(async () => {
    const res = await api.get(`/api/scans/${scanId}/dynamic`);
    setLoading(false);
    if (res.status === 401) {
      onSessionEnd?.();
      return;
    }
    if (res.status === 200) {
      setJob((res.data.dynamic as DynamicJob) ?? null);
    }
  }, [scanId, onSessionEnd]);

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
  const active = job?.status === "queued" || job?.status === "running";

  return (
    <div className="bg-white rounded-xl border border-slate-200 p-5 space-y-4">
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <div className="flex items-center gap-2">
            <h3 className="font-semibold text-slate-800">Dynamic Browser Analysis (Isolated Docker)</h3>
            {job && <Badge tone={STATUS_TONE[job.status]}>{job.status.replace("_", " ")}</Badge>}
          </div>
          <p className="text-xs text-slate-500 mt-0.5">
            Executes the page in a disposable Chromium container to observe runtime redirects, scripts, DOM changes, and evaluate AI 2 on rendered HTML.
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

      {job && (job.status === "completed" || job.status === "partial" || job.status === "timed_out") && (
        <div className="space-y-4">
          {ai2d && (
            <div className="rounded-lg border border-slate-200 bg-slate-50 p-4 space-y-2">
              <div className="flex items-center justify-between gap-2">
                <span className="text-xs font-semibold text-slate-700">AI 2 — Rendered DOM Prediction</span>
                {ai2d.flagged !== null && ai2d.flagged !== undefined && (
                  <Badge tone={ai2d.flagged ? "red" : "green"}>{ai2d.flagged ? "Flagged" : "Below threshold"}</Badge>
                )}
              </div>
              <RiskBar
                label="Rendered-DOM phishing probability"
                value={ai2d.percent ?? 0}
                display={`${ai2d.percent ?? 0}%`}
                tone={ai2d.flagged ? "red" : "green"}
                note={
                  ai2d.probability_calibrated != null && ai2d.threshold != null
                    ? `Calibrated: ${(ai2d.probability_calibrated * 100).toFixed(1)}% (threshold ${(ai2d.threshold * 100).toFixed(1)}%) · ${ai2d.model_version ?? ""}`
                    : ai2d.model_version
                }
              />
              {ai2d.signals && ai2d.signals.length > 0 && (
                <ul className="list-disc pl-5 text-xs text-slate-600 space-y-0.5 pt-1">
                  {ai2d.signals.map((s, i) => (
                    <li key={i}>{s}</li>
                  ))}
                </ul>
              )}
              <p className="text-[11px] text-slate-400">{ai2d.note}</p>
            </div>
          )}

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
      )}
    </div>
  );
}
