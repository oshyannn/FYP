import { useCallback, useEffect, useState } from "react";
import type { FormEvent } from "react";
import { api, problem } from "../../../api";
import Badge from "../../../components/feedback/Badge";
import ReplyBox from "../../../components/feedback/ReplyBox";
import ThreadView from "../../../components/feedback/ThreadView";
import { Alert } from "../../../components/ui";
import { LEVEL_STYLE } from "../../../lib/analysis";
import type { ScanRecord } from "../../../lib/analysis";
import { CATEGORY_OPTIONS, STATUS_OPTIONS, categoryForScan, categoryLabel, patchFeedback, statusLabel, statusTone } from "../../../lib/feedback";
import type { FeedbackCategory, FeedbackRow, FeedbackThread } from "../../../lib/feedback";

interface Props {
  /** set when the user came from a scan result ("Report wrong detection") */
  initialScan?: ScanRecord | null;
  onSessionEnd: () => void;
}

type View = "list" | "form" | "thread";
const PER_PAGE = 10;
const input = "w-full px-3.5 py-2.5 border border-slate-300 rounded-lg text-sm placeholder-slate-400 focus:outline-none focus:border-[#1e3a5f] focus:ring-2 focus:ring-[#1e3a5f]/10";

export default function Feedback({ initialScan, onSessionEnd }: Props) {
  const [view, setView] = useState<View>(initialScan ? "form" : "list");
  const [thread, setThread] = useState<FeedbackThread | null>(null);
  const [editing, setEditing] = useState(false);
  const [error, setError] = useState("");
  const [done, setDone] = useState("");

  // list
  const [rows, setRows] = useState<FeedbackRow[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [q, setQ] = useState("");
  const [status, setStatus] = useState("");
  const [page, setPage] = useState(1);

  // form
  const [category, setCategory] = useState<FeedbackCategory>(initialScan ? categoryForScan(initialScan.risk_level) : "false_positive");
  const [subject, setSubject] = useState(initialScan ? `Wrong detection: ${initialScan.domain}` : "");
  const [message, setMessage] = useState("");
  const [historyId, setHistoryId] = useState(initialScan?.id ?? "");
  const [scans, setScans] = useState<ScanRecord[]>([]);
  const [fields, setFields] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState(false);
  const [replyError, setReplyError] = useState("");

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

  const loadList = useCallback(async () => {
    setLoading(true);
    const qs = new URLSearchParams({ page: String(page), per_page: String(PER_PAGE) });
    if (q) qs.set("search", q);
    if (status) qs.set("status", status);
    const res = await api.get(`/api/feedback?${qs.toString()}`);
    setLoading(false);
    if (ended(res.status)) return;
    if (res.status === 200) {
      setRows(res.data.feedback as FeedbackRow[]);
      setTotal(res.data.total as number);
    } else setError(problem(res).message);
  }, [q, status, page]);

  useEffect(() => {
    if (view === "list") loadList();
  }, [view, loadList]);

  // the user's recent scans, offered for attaching
  useEffect(() => {
    if (view !== "form") return;
    (async () => {
      const res = await api.get("/api/scans?per_page=50");
      if (ended(res.status)) return;
      if (res.status === 200) setScans(res.data.scans as ScanRecord[]);
    })();
  }, [view]);

  async function open(id: string) {
    setError("");
    setDone("");
    const res = await api.get(`/api/feedback/${id}`);
    if (ended(res.status)) return;
    if (res.status === 200) {
      setThread(res.data.feedback as FeedbackThread);
      setReplyError("");
      setView("thread");
    } else setError(problem(res).message);
  }

  function startNew() {
    setEditing(false);
    setCategory("false_positive");
    setSubject("");
    setMessage("");
    setHistoryId("");
    setFields({});
    setError("");
    setDone("");
    setView("form");
  }

  function startEdit(t: FeedbackThread) {
    setEditing(true);
    setCategory(t.category);
    setSubject(t.subject);
    setMessage(t.message);
    setHistoryId(t.attached_scan?.id ?? "");
    setFields({});
    setError("");
    setView("form");
  }

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (busy) return;
    const local: Record<string, string> = {};
    if (subject.trim().length < 3) local.subject = "Enter a subject (at least 3 characters).";
    if (message.trim().length < 10) local.message = "Describe your feedback (at least 10 characters).";
    setFields(local);
    if (Object.keys(local).length) return;
    setBusy(true);
    setError("");
    const payload = { category, subject: subject.trim(), message: message.trim(), history_id: historyId || null };
    const res =
      editing && thread
        ? await patchFeedback(`/api/feedback/${thread.id}`, payload)
        : await api.post("/api/feedback", payload);
    setBusy(false);
    if (ended(res.status)) return;
    if (res.status === 200 || res.status === 201) {
      setThread(res.data.feedback as FeedbackThread);
      setDone(editing ? "Your feedback was updated." : "Thank you. Your feedback was submitted.");
      setEditing(false);
      setView("thread");
      return;
    }
    const p = problem(res);
    setFields(p.fields);
    if (!Object.keys(p.fields).length) setError(p.message);
  }

  async function reply(text: string): Promise<boolean> {
    if (!thread) return false;
    setBusy(true);
    setReplyError("");
    const res = await api.post(`/api/feedback/${thread.id}/replies`, { message: text });
    setBusy(false);
    if (ended(res.status)) return false;
    if (res.status === 201) {
      setThread(res.data.feedback as FeedbackThread);
      return true;
    }
    setReplyError(problem(res).message);
    return false;
  }

  const pages = Math.max(1, Math.ceil(total / PER_PAGE));

  if (view === "form") {
    return (
      <div className="max-w-2xl mx-auto space-y-5">
        <button onClick={() => (editing && thread ? setView("thread") : setView("list"))} className="text-slate-500 hover:text-slate-700 text-sm">
          ← Back
        </button>
        <h2 className="text-xl font-bold text-slate-900">{editing ? "Edit Feedback" : "New Feedback"}</h2>
        {error && <Alert kind="error">{error}</Alert>}
        <form onSubmit={submit} className="bg-white rounded-xl border border-slate-200 p-6 space-y-4" noValidate>
          <div>
            <label htmlFor="fb-category" className="block text-sm font-medium text-slate-700 mb-1.5">Type</label>
            <select id="fb-category" value={category} onChange={(e) => setCategory(e.target.value as FeedbackCategory)} className={input}>
              {CATEGORY_OPTIONS.map(([v, l]) => (
                <option key={v} value={v}>{l}</option>
              ))}
            </select>
            {fields.category && <p className="mt-1 text-xs text-red-600">{fields.category}</p>}
          </div>
          <div>
            <label htmlFor="fb-subject" className="block text-sm font-medium text-slate-700 mb-1.5">Subject</label>
            <input id="fb-subject" value={subject} onChange={(e) => setSubject(e.target.value)} maxLength={200} className={input} placeholder="Short summary" aria-invalid={fields.subject ? true : undefined} />
            {fields.subject && <p className="mt-1 text-xs text-red-600">{fields.subject}</p>}
          </div>
          <div>
            <label htmlFor="fb-message" className="block text-sm font-medium text-slate-700 mb-1.5">Message</label>
            <textarea id="fb-message" value={message} onChange={(e) => setMessage(e.target.value)} maxLength={4000} rows={5} className={`${input} resize-none`} placeholder="Describe your feedback in detail..." aria-invalid={fields.message ? true : undefined} />
            {fields.message && <p className="mt-1 text-xs text-red-600">{fields.message}</p>}
          </div>
          <div>
            <label htmlFor="fb-scan" className="block text-sm font-medium text-slate-700 mb-1.5">Attach a scan result (optional)</label>
            <select id="fb-scan" value={historyId} onChange={(e) => setHistoryId(e.target.value)} className={input}>
              <option value="">No scan attached</option>
              {historyId && !scans.some((s) => s.id === historyId) && <option value={historyId}>Currently attached scan</option>}
              {scans.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.domain} · {LEVEL_STYLE[s.risk_level].label} · {new Date(s.scanned_at).toLocaleDateString()}
                </option>
              ))}
            </select>
            {fields.history_id && <p className="mt-1 text-xs text-red-600">{fields.history_id}</p>}
            {scans.length === 0 && <p className="mt-1 text-xs text-slate-500">You have no scan results yet. You can still send feedback without one.</p>}
          </div>
          <div className="flex gap-3 pt-1">
            <button type="button" onClick={() => (editing && thread ? setView("thread") : setView("list"))} className="flex-1 border border-slate-300 text-slate-700 py-2.5 rounded-lg text-sm font-medium hover:bg-slate-50">
              Cancel
            </button>
            <button type="submit" disabled={busy} className="flex-1 bg-[#1e3a5f] text-white py-2.5 rounded-lg text-sm font-semibold hover:bg-[#162d4a] disabled:opacity-60">
              {busy ? "Please wait…" : editing ? "Save changes" : "Submit"}
            </button>
          </div>
        </form>
      </div>
    );
  }

  if (view === "thread" && thread) {
    return (
      <div className="max-w-3xl mx-auto space-y-5">
        <button onClick={() => { setView("list"); setDone(""); }} className="text-slate-500 hover:text-slate-700 text-sm">
          ← Back to Feedback
        </button>
        {done && <Alert kind="success">{done}</Alert>}
        {error && <Alert kind="error">{error}</Alert>}
        <ThreadView
          thread={thread}
          actions={
            thread.can_edit && (
              <button onClick={() => startEdit(thread)} className="border border-slate-300 text-slate-700 px-3.5 py-2 rounded-lg text-sm font-medium hover:bg-slate-50">
                Edit
              </button>
            )
          }
          footer={<ReplyBox closed={!thread.can_reply} busy={busy} error={replyError} onSend={reply} />}
        />
      </div>
    );
  }

  return (
    <div className="max-w-5xl space-y-5">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-slate-900">Feedback</h2>
          <p className="text-slate-500 text-sm mt-0.5">Report a wrong detection or tell us how to improve SafeBrowse.</p>
        </div>
        <button onClick={startNew} className="bg-[#1e3a5f] text-white px-4 py-2.5 rounded-lg text-sm font-semibold hover:bg-[#162d4a]">
          New Feedback
        </button>
      </div>

      {error && <Alert kind="error">{error}</Alert>}

      <div className="flex flex-wrap gap-3">
        <input value={search} onChange={(e) => setSearch(e.target.value)} maxLength={100} aria-label="Search feedback" placeholder="Search feedback..." className="flex-1 min-w-36 px-3.5 py-2 border border-slate-300 rounded-lg text-sm placeholder-slate-400 bg-white focus:outline-none focus:border-[#1e3a5f]" />
        <select value={status} onChange={(e) => { setStatus(e.target.value); setPage(1); }} aria-label="Filter by status" className="px-3.5 py-2 border border-slate-300 rounded-lg text-sm bg-white text-slate-700">
          <option value="">All Status</option>
          {STATUS_OPTIONS.map(([v, l]) => (
            <option key={v} value={v}>{l}</option>
          ))}
        </select>
      </div>

      <div className="bg-white rounded-xl border border-slate-200 overflow-hidden">
        <table className="w-full">
          <thead>
            <tr className="text-xs text-slate-500 bg-slate-50 border-b border-slate-200">
              {["Subject", "Type", "Status", "Submitted", "Replies", "Action"].map((h) => (
                <th key={h} className="text-left px-5 py-3 font-medium">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {rows.map((r) => (
              <tr key={r.id} className="hover:bg-slate-50 transition-colors">
                <td className="px-5 py-3.5 text-sm font-medium text-slate-800 max-w-xs truncate" title={r.subject}>{r.subject}</td>
                <td className="px-5 py-3.5 text-sm text-slate-600">{categoryLabel(r.category)}</td>
                <td className="px-5 py-3.5"><Badge tone={statusTone(r.status)}>{statusLabel(r.status)}</Badge></td>
                <td className="px-5 py-3.5 text-sm text-slate-500">{new Date(r.created_at).toLocaleDateString()}</td>
                <td className="px-5 py-3.5 text-sm text-slate-600">{r.reply_count}</td>
                <td className="px-5 py-3.5">
                  <button onClick={() => open(r.id)} className="text-[#1e3a5f] text-sm font-medium hover:underline">View</button>
                </td>
              </tr>
            ))}
            {rows.length === 0 && (
              <tr>
                <td colSpan={6} className="px-5 py-10 text-center text-slate-400 text-sm">
                  {loading ? "Loading…" : q || status ? "No matching feedback found." : "You have not submitted any feedback yet."}
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
