import { useCallback, useEffect, useState } from "react";
import { api, problem } from "../api";
import Badge from "../components/feedback/Badge";
import ReplyBox from "../components/feedback/ReplyBox";
import ThreadView from "../components/feedback/ThreadView";
import { Alert } from "../components/ui";
import { CATEGORY_OPTIONS, categoryLabel, statusLabel, statusTone } from "../lib/feedback";
import type { FeedbackRow, FeedbackStatus, FeedbackThread } from "../lib/feedback";

interface Props {
  onSessionEnd: () => void;
}

const PER_PAGE = 10;
type Filter = "" | FeedbackStatus;
type After = "" | "in_progress" | "resolved";

export default function StaffFeedback({ onSessionEnd }: Props) {
  const [filter, setFilter] = useState<Filter>("open");
  const [category, setCategory] = useState("");
  const [search, setSearch] = useState("");
  const [q, setQ] = useState("");
  const [page, setPage] = useState(1);
  const [rows, setRows] = useState<FeedbackRow[]>([]);
  const [total, setTotal] = useState(0);
  const [counts, setCounts] = useState({ open: 0, in_progress: 0, resolved: 0, closed: 0 });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [done, setDone] = useState("");

  const [thread, setThread] = useState<FeedbackThread | null>(null);
  const [busy, setBusy] = useState(false);
  const [replyError, setReplyError] = useState("");
  const [after, setAfter] = useState<After>("");
  const [confirmClose, setConfirmClose] = useState(false);

  const ended = (s: number) => {
    if (s === 401) {
      onSessionEnd();
      return true;
    }
    return false;
  };

  useEffect(() => {
    const t = window.setTimeout(() => {
      setQ(search.trim());
      setPage(1);
    }, 300);
    return () => window.clearTimeout(t);
  }, [search]);

  const load = useCallback(async () => {
    setLoading(true);
    const qs = new URLSearchParams({ page: String(page), per_page: String(PER_PAGE) });
    if (filter) qs.set("status", filter);
    if (category) qs.set("category", category);
    if (q) qs.set("search", q);
    const res = await api.get(`/api/staff/feedback?${qs.toString()}`);
    setLoading(false);
    if (ended(res.status)) return;
    if (res.status !== 200) return setError(problem(res).message);
    setRows(res.data.feedback as FeedbackRow[]);
    setTotal(res.data.total as number);
    setCounts(res.data.counts);
  }, [filter, category, q, page]);

  useEffect(() => {
    if (!thread) load();
  }, [thread, load]);

  async function open(id: string) {
    setError("");
    setDone("");
    const res = await api.get(`/api/staff/feedback/${id}`);
    if (ended(res.status)) return;
    if (res.status === 200) {
      setThread(res.data.feedback as FeedbackThread);
      setReplyError("");
      setAfter("");
    } else setError(problem(res).message);
  }

  async function reply(text: string): Promise<boolean> {
    if (!thread) return false;
    setBusy(true);
    setReplyError("");
    const res = await api.post(`/api/staff/feedback/${thread.id}/replies`, { message: text, status: after || undefined });
    setBusy(false);
    if (ended(res.status)) return false;
    if (res.status === 201) {
      setThread(res.data.feedback as FeedbackThread);
      setAfter("");
      return true;
    }
    setReplyError(problem(res).message);
    return false;
  }

  async function setStatus(status: "in_progress" | "resolved" | "closed") {
    if (!thread || busy) return;
    setBusy(true);
    setError("");
    const res = await api.post(`/api/staff/feedback/${thread.id}/status`, { status });
    setBusy(false);
    setConfirmClose(false);
    if (ended(res.status)) return;
    if (res.status === 200) {
      setThread(res.data.feedback as FeedbackThread);
      setDone(status === "closed" ? "Feedback closed." : "Status updated.");
    } else setError(problem(res).message);
  }

  const pages = Math.max(1, Math.ceil(total / PER_PAGE));

  if (thread) {
    const st = thread.status;
    const btn = "border border-slate-300 text-slate-700 px-3.5 py-2 rounded-lg text-sm font-medium hover:bg-slate-50 disabled:opacity-50";
    return (
      <div className="max-w-3xl mx-auto space-y-5">
        <button onClick={() => { setThread(null); setDone(""); }} className="text-slate-500 hover:text-slate-700 text-sm">
          ← Back to Feedback
        </button>
        {done && <Alert kind="success">{done}</Alert>}
        {error && <Alert kind="error">{error}</Alert>}
        <ThreadView
          thread={thread}
          staff
          actions={
            st !== "closed" && (
              <>
                {st !== "in_progress" && <button disabled={busy} onClick={() => setStatus("in_progress")} className={btn}>Mark in review</button>}
                {st !== "resolved" && <button disabled={busy} onClick={() => setStatus("resolved")} className={btn}>Mark resolved</button>}
                <button disabled={busy} onClick={() => setConfirmClose(true)} className="border border-red-300 text-red-600 px-3.5 py-2 rounded-lg text-sm font-medium hover:bg-red-50 disabled:opacity-50">
                  Close feedback
                </button>
              </>
            )
          }
          footer={
            <ReplyBox
              closed={!thread.can_reply}
              busy={busy}
              error={replyError}
              onSend={reply}
              extra={
                <label className="flex items-center gap-2">
                  <span>After sending:</span>
                  <select value={after} onChange={(e) => setAfter(e.target.value as After)} className="px-2.5 py-1.5 border border-slate-300 rounded-lg text-sm bg-white">
                    <option value="">Keep the status</option>
                    <option value="in_progress">Mark in review</option>
                    <option value="resolved">Mark resolved</option>
                  </select>
                </label>
              }
            />
          }
        />
        {confirmClose && (
          <div className="fixed inset-0 z-50 bg-black/40 flex items-center justify-center p-4" role="dialog" aria-modal="true" aria-labelledby="close-title">
            <div className="bg-white rounded-2xl p-6 max-w-sm w-full shadow-xl">
              <h3 id="close-title" className="font-semibold text-slate-900 mb-2">Close this feedback?</h3>
              <p className="text-slate-500 text-sm mb-5">Nobody can reply to it afterwards and it cannot be reopened.</p>
              <div className="flex gap-3">
                <button onClick={() => setConfirmClose(false)} className="flex-1 border border-slate-300 text-slate-700 py-2.5 rounded-lg text-sm font-medium">Cancel</button>
                <button onClick={() => setStatus("closed")} disabled={busy} className="flex-1 bg-red-600 text-white py-2.5 rounded-lg text-sm font-medium hover:bg-red-700 disabled:opacity-60">
                  {busy ? "Please wait…" : "Close feedback"}
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    );
  }

  const chips: { key: Filter; label: string; n?: number; cls: string }[] = [
    { key: "open", label: "Open", n: counts.open, cls: "bg-blue-50 border-blue-200 text-blue-700" },
    { key: "in_progress", label: "In Review", n: counts.in_progress, cls: "bg-amber-50 border-amber-200 text-amber-700" },
    { key: "resolved", label: "Resolved", n: counts.resolved, cls: "bg-green-50 border-green-200 text-green-700" },
    { key: "closed", label: "Closed", n: counts.closed, cls: "bg-slate-50 border-slate-200 text-slate-700" },
    { key: "", label: "All", cls: "bg-white border-slate-200 text-slate-700" },
  ];

  return (
    <div className="max-w-6xl space-y-5">
      <div>
        <h2 className="text-xl font-bold text-slate-900">User Feedback</h2>
        <p className="text-slate-500 text-sm mt-0.5">Review feedback and wrong-detection reports, reply and close them.</p>
      </div>
      {error && <Alert kind="error">{error}</Alert>}
      <div className="flex flex-wrap gap-3">
        {chips.map((c) => (
          <button key={c.label} onClick={() => { setFilter(c.key); setPage(1); }} aria-pressed={filter === c.key}
            className={`border rounded-xl px-4 py-2.5 text-sm font-semibold ${c.cls} ${filter === c.key ? "ring-2 ring-[#1e3a5f]/40" : "opacity-80 hover:opacity-100"}`}>
            {c.n !== undefined ? `${c.n} ` : ""}{c.label}
          </button>
        ))}
      </div>
      <div className="flex flex-wrap gap-3">
        <input value={search} onChange={(e) => setSearch(e.target.value)} maxLength={100} aria-label="Search feedback" placeholder="Search subject, message, name or email..." className="flex-1 min-w-48 px-3.5 py-2 border border-slate-300 rounded-lg text-sm placeholder-slate-400 bg-white focus:outline-none focus:border-[#1e3a5f]" />
        <select value={category} onChange={(e) => { setCategory(e.target.value); setPage(1); }} aria-label="Filter by type" className="px-3.5 py-2 border border-slate-300 rounded-lg text-sm bg-white text-slate-700">
          <option value="">All Types</option>
          {CATEGORY_OPTIONS.map(([v]) => (
            <option key={v} value={v}>{categoryLabel(v)}</option>
          ))}
        </select>
      </div>

      <div className="bg-white rounded-xl border border-slate-200 overflow-hidden">
        <table className="w-full">
          <thead>
            <tr className="text-xs text-slate-500 bg-slate-50 border-b border-slate-200">
              {["Subject", "From", "Type", "Status", "Submitted", "Replies", "Action"].map((h) => (
                <th key={h} className="text-left px-5 py-3 font-medium">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {rows.map((r) => (
              <tr key={r.id} className="hover:bg-slate-50 transition-colors">
                <td className="px-5 py-3.5 text-sm font-medium text-slate-800 max-w-xs truncate" title={r.subject}>
                  {r.subject}
                  {r.has_scan && <span className="ml-2 text-[10px] text-slate-400 border border-slate-200 rounded px-1">scan attached</span>}
                </td>
                <td className="px-5 py-3.5 text-sm text-slate-600">{r.author_name ?? r.author_email}</td>
                <td className="px-5 py-3.5 text-sm text-slate-600">{categoryLabel(r.category)}</td>
                <td className="px-5 py-3.5"><Badge tone={statusTone(r.status)}>{statusLabel(r.status)}</Badge></td>
                <td className="px-5 py-3.5 text-sm text-slate-500">{new Date(r.created_at).toLocaleDateString()}</td>
                <td className="px-5 py-3.5 text-sm text-slate-600">{r.reply_count}</td>
                <td className="px-5 py-3.5">
                  <button onClick={() => open(r.id)} className="text-[#1e3a5f] text-sm font-medium hover:underline">Open</button>
                </td>
              </tr>
            ))}
            {rows.length === 0 && (
              <tr>
                <td colSpan={7} className="px-5 py-10 text-center text-slate-400 text-sm">
                  {loading ? "Loading…" : "No feedback found."}
                </td>
              </tr>
            )}
          </tbody>
        </table>
        {total > PER_PAGE && (
          <div className="px-5 py-3.5 border-t border-slate-100 flex items-center justify-between text-sm text-slate-600">
            <span>Showing {(page - 1) * PER_PAGE + 1}–{Math.min(page * PER_PAGE, total)} of {total}</span>
            <div className="flex gap-1">
              {Array.from({ length: pages }, (_, i) => i + 1).map((p) => (
                <button key={p} onClick={() => setPage(p)} aria-current={p === page ? "page" : undefined} className={`w-8 h-8 rounded-lg text-sm font-medium ${p === page ? "bg-[#1e3a5f] text-white" : "hover:bg-slate-100 text-slate-600"}`}>
                  {p}
                </button>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
