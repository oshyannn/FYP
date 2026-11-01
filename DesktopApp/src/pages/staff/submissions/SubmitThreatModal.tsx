import { useState } from "react";
import { api, problem } from "../../../api";
import Modal from "../../../components/Modal";
import { Alert } from "../../../components/ui";
import { scoreBarClass, SUBMISSION_CATEGORIES } from "../../../lib/approvals";

interface Props {
  onClose: () => void;
  onSubmitted: () => void;
  onSessionEnd: () => void;
}

const empty = { url: "", category: "phishing", score: "", notes: "" };
const STEPS = ["You Submit", "Admin Reviews", "Published to All"];

const fieldCls = (bad: boolean) =>
  `w-full px-3.5 py-2.5 border rounded-lg text-sm placeholder-slate-400 focus:outline-none focus:ring-2 transition-colors ${
    bad ? "border-red-400 focus:border-red-400 focus:ring-red-100" : "border-slate-300 focus:border-[#1e3a5f] focus:ring-[#1e3a5f]/10"
  }`;

// Employer: report a threat URL. It goes to the administrators' approval queue before it is published.
export default function SubmitThreatModal({ onClose, onSubmitted, onSessionEnd }: Props) {
  const [form, setForm] = useState(empty);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const set = (k: keyof typeof empty, v: string) => {
    setForm((f) => ({ ...f, [k]: v }));
    setErrors((e) => ({ ...e, [k]: "" }));
  };

  function validate(): boolean {
    const e: Record<string, string> = {};
    if (!form.url.trim()) e.url = "URL is required.";
    const n = Number(form.score);
    if (form.score.trim() === "" || Number.isNaN(n) || n < 0 || n > 100) e.score = "Enter a risk score between 0 and 100.";
    if (form.notes.trim().length < 3) e.notes = "Notes / reason is required.";
    setErrors(e);
    return Object.keys(e).length === 0;
  }

  async function submit() {
    if (busy || !validate()) return;
    setBusy(true);
    setError("");
    const res = await api.post("/api/staff/threat-submissions", {
      url: form.url.trim(),
      category: form.category,
      score: Number(form.score),
      notes: form.notes.trim(),
    });
    setBusy(false);
    if (res.status === 401) return onSessionEnd();
    if (res.status === 201) return onSubmitted();
    const p = problem(res);
    if (Object.keys(p.fields).length) setErrors(p.fields);
    else setError(res.status === 429 ? "Too many submissions. Wait a moment and try again." : p.message);
  }

  const score = Number(form.score);
  const showBar = form.score.trim() !== "" && !Number.isNaN(score);

  return (
    <Modal
      title="Submit Threat URL"
      subtitle="Your submission will be sent to the Admin Approval Queue before being published."
      width="lg"
      onClose={onClose}
      footer={
        <>
          <button onClick={onClose} className="flex-1 border border-slate-300 text-slate-700 py-2.5 rounded-lg text-sm font-medium hover:bg-slate-50">
            Cancel
          </button>
          <button onClick={submit} disabled={busy} className="flex-1 bg-[#1e3a5f] text-white py-2.5 rounded-lg text-sm font-semibold hover:bg-[#162d4a] disabled:opacity-60">
            {busy ? "Submitting…" : "Submit for Review"}
          </button>
        </>
      }
    >
      <div className="flex items-center mb-5">
        {STEPS.map((step, i) => (
          <div key={step} className="flex items-center flex-1">
            <div className="flex flex-col items-center flex-1">
              <div className={`w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold ${i === 0 ? "bg-[#1e3a5f] text-white" : "bg-slate-200 text-slate-500"}`}>{i + 1}</div>
              <span className="text-[10px] text-slate-500 mt-1 text-center leading-tight">{step}</span>
            </div>
            {i < 2 && <div className="w-8 h-px bg-slate-300 shrink-0 mb-3" />}
          </div>
        ))}
      </div>

      {error && <Alert kind="error">{error}</Alert>}

      <div className="space-y-4">
        <div>
          <label htmlFor="th-url" className="block text-sm font-medium text-slate-700 mb-1.5">
            Threat URL <span className="text-red-500">*</span>
          </label>
          <input id="th-url" value={form.url} maxLength={2048} onChange={(e) => set("url", e.target.value)} placeholder="https://malicious-example.com" className={`${fieldCls(!!errors.url)} font-mono`} />
          {errors.url && <p className="text-red-500 text-xs mt-1">{errors.url}</p>}
        </div>

        <div className="grid grid-cols-2 gap-4">
          <div>
            <label htmlFor="th-cat" className="block text-sm font-medium text-slate-700 mb-1.5">
              Threat Category <span className="text-red-500">*</span>
            </label>
            <select id="th-cat" value={form.category} onChange={(e) => set("category", e.target.value)} className="w-full px-3.5 py-2.5 border border-slate-300 rounded-lg text-sm bg-white text-slate-700 focus:outline-none focus:border-[#1e3a5f]">
              {SUBMISSION_CATEGORIES.map(([v, l]) => (
                <option key={v} value={v}>
                  {l}
                </option>
              ))}
            </select>
            {errors.category && <p className="text-red-500 text-xs mt-1">{errors.category}</p>}
          </div>
          <div>
            <label htmlFor="th-score" className="block text-sm font-medium text-slate-700 mb-1.5">
              Risk Score (0–100) <span className="text-red-500">*</span>
            </label>
            <input id="th-score" type="number" min={0} max={100} value={form.score} onChange={(e) => set("score", e.target.value)} placeholder="e.g. 95" className={fieldCls(!!errors.score)} />
            {errors.score && <p className="text-red-500 text-xs mt-1">{errors.score}</p>}
            {showBar && (
              <div className="mt-1.5 h-1.5 bg-slate-100 rounded-full overflow-hidden">
                <div className={`h-full rounded-full ${scoreBarClass(score)}`} style={{ width: `${Math.min(100, Math.max(0, score))}%` }} />
              </div>
            )}
          </div>
        </div>

        <div>
          <label htmlFor="th-notes" className="block text-sm font-medium text-slate-700 mb-1.5">
            Notes / Reason <span className="text-red-500">*</span>
          </label>
          <textarea
            id="th-notes"
            value={form.notes}
            maxLength={1000}
            onChange={(e) => set("notes", e.target.value)}
            rows={3}
            placeholder="Describe why this URL is a threat. The more detail you provide, the faster admin can review it."
            className={`${fieldCls(!!errors.notes)} resize-none`}
          />
          {errors.notes && <p className="text-red-500 text-xs mt-1">{errors.notes}</p>}
        </div>
      </div>
    </Modal>
  );
}
