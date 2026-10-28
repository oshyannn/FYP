import { useState } from "react";
import type { ReactNode } from "react";

interface Props {
  closed: boolean;
  busy: boolean;
  error?: string;
  /** resolves true when the reply was saved (the box is then cleared) */
  onSend: (message: string) => Promise<boolean>;
  extra?: ReactNode;
}

export default function ReplyBox({ closed, busy, error, onSend, extra }: Props) {
  const [text, setText] = useState("");

  if (closed) {
    return (
      <div className="bg-slate-100 border border-slate-200 rounded-xl p-4 text-sm text-slate-600" role="status">
        This feedback is closed, so it cannot be replied to.
      </div>
    );
  }

  async function send() {
    if (busy || text.trim().length < 2) return;
    if (await onSend(text.trim())) setText("");
  }

  return (
    <div className="bg-white rounded-xl border border-slate-200 p-4">
      <label htmlFor="reply-text" className="block text-sm font-medium text-slate-700 mb-1.5">Reply</label>
      <textarea
        id="reply-text"
        value={text}
        onChange={(e) => setText(e.target.value)}
        maxLength={4000}
        rows={3}
        placeholder="Write your reply..."
        className="w-full px-3.5 py-2.5 border border-slate-300 rounded-lg text-sm placeholder-slate-400 focus:outline-none focus:border-[#1e3a5f] focus:ring-2 focus:ring-[#1e3a5f]/10 resize-none"
      />
      {error && <p className="text-xs text-red-600 mt-1" role="alert">{error}</p>}
      <div className="flex items-center justify-between gap-3 mt-3 flex-wrap">
        <div className="text-sm text-slate-600">{extra}</div>
        <button
          onClick={send}
          disabled={busy || text.trim().length < 2}
          className="bg-[#1e3a5f] text-white px-5 py-2.5 rounded-lg text-sm font-semibold hover:bg-[#162d4a] disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {busy ? "Sending…" : "Send reply"}
        </button>
      </div>
    </div>
  );
}
