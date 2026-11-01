import { useState } from "react";
import StatusBadge from "../components/StatusBadge";

interface Message {
  id: number;
  from: string;
  role: "user" | "admin" | "employer";
  avatar: string;
  text: string;
  time: string;
}

interface FeedbackThread {
  id: number;
  subject: string;
  type: string;
  url: string;
  date: string;
  status: string;
  unread: boolean;
  messages: Message[];
}

const initialThreads: FeedbackThread[] = [
  {
    id: 1,
    subject: "False Positive — example.com flagged as suspicious",
    type: "False Positive",
    url: "example.com",
    date: "30 Aug 2026",
    status: "In Review",
    unread: true,
    messages: [
      { id: 1, from: "John Tan", role: "user", avatar: "JT", text: "This website was incorrectly flagged as suspicious. It is a legitimate company site that I use daily for work. Please review this detection.", time: "30 Aug 2026, 09:15 AM" },
      { id: 2, from: "Admin (SafeBrowse)", role: "admin", avatar: "AD", text: "Thank you for your report, John. We have received your feedback and our team is currently reviewing the detection result for example.com. We will update you shortly.", time: "30 Aug 2026, 02:30 PM" },
      { id: 3, from: "Employer (TechCorp)", role: "employer", avatar: "EM", text: "I can also confirm that example.com is a legitimate domain used by our organisation. Flagging it as suspicious is causing disruption to our team's daily workflow.", time: "31 Aug 2026, 09:00 AM" },
    ],
  },
  {
    id: 2,
    subject: "Incorrect Detection — safe-shop.com marked malicious",
    type: "Incorrect Detection",
    url: "safe-shop.com",
    date: "28 Aug 2026",
    status: "Responded",
    unread: false,
    messages: [
      { id: 1, from: "John Tan", role: "user", avatar: "JT", text: "The site safe-shop.com was marked as malicious but it is a trusted e-commerce platform I have used for over 3 years without any issues.", time: "28 Aug 2026, 10:00 AM" },
      { id: 2, from: "Admin (SafeBrowse)", role: "admin", avatar: "AD", text: "We have investigated the report and updated our database. The URL safe-shop.com has been reclassified as Safe. We apologise for the inconvenience. Thank you for helping us improve SafeBrowse.", time: "29 Aug 2026, 09:00 AM" },
    ],
  },
  {
    id: 3,
    subject: "System Problem — Extension not syncing with dashboard",
    type: "System Problem",
    url: "",
    date: "25 Aug 2026",
    status: "Closed",
    unread: false,
    messages: [
      { id: 1, from: "John Tan", role: "user", avatar: "JT", text: "The browser extension stopped syncing with the dashboard. My detection history is not updating in real time since yesterday.", time: "25 Aug 2026, 11:20 AM" },
      { id: 2, from: "Admin (SafeBrowse)", role: "admin", avatar: "AD", text: "This issue was caused by a temporary server sync delay and has been resolved on our end. Please restart your browser extension and clear the extension cache. Let us know if the issue persists.", time: "26 Aug 2026, 08:45 AM" },
      { id: 3, from: "John Tan", role: "user", avatar: "JT", text: "It is working now after restarting the extension. Thank you for the quick fix!", time: "26 Aug 2026, 10:00 AM" },
      { id: 4, from: "Admin (SafeBrowse)", role: "admin", avatar: "AD", text: "Great to hear that! We are closing this ticket. Feel free to open a new one if any issues arise.", time: "26 Aug 2026, 10:30 AM" },
    ],
  },
];

function avatarColor(role: "user" | "admin" | "employer") {
  if (role === "admin") return "bg-[#1e3a5f] text-white";
  if (role === "employer") return "bg-purple-600 text-white";
  return "bg-slate-200 text-slate-700";
}

function roleLabel(role: "user" | "admin" | "employer") {
  if (role === "admin") return "Admin";
  if (role === "employer") return "Employer";
  return "You";
}

export default function Feedback() {
  const [view, setView] = useState<"inbox" | "compose">("inbox");
  const [threads, setThreads] = useState<FeedbackThread[]>(initialThreads);
  const [selected, setSelected] = useState<FeedbackThread | null>(null);
  const [replyText, setReplyText] = useState("");
  const [form, setForm] = useState({ type: "", url: "", message: "" });
  const [composeSuccess, setComposeSuccess] = useState(false);

  const openThread = (t: FeedbackThread) => {
    setThreads(prev => prev.map(th => th.id === t.id ? { ...th, unread: false } : th));
    setSelected({ ...t, unread: false });
    setReplyText("");
  };

  const sendReply = () => {
    if (!replyText.trim() || !selected) return;
    const newMsg: Message = {
      id: selected.messages.length + 1,
      from: "John Tan",
      role: "user",
      avatar: "JT",
      text: replyText.trim(),
      time: "31 Aug 2026, " + new Date().toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit" }),
    };
    const updated = threads.map(t =>
      t.id === selected.id ? { ...t, messages: [...t.messages, newMsg] } : t
    );
    setThreads(updated);
    const updatedThread = updated.find(t => t.id === selected.id)!;
    setSelected(updatedThread);
    setReplyText("");
  };

  const submitNew = () => {
    const newThread: FeedbackThread = {
      id: threads.length + 1,
      subject: `${form.type}${form.url ? " — " + form.url : ""}`,
      type: form.type || "Other",
      url: form.url,
      date: "31 Aug 2026",
      status: "Pending",
      unread: false,
      messages: [
        { id: 1, from: "John Tan", role: "user", avatar: "JT", text: form.message, time: "31 Aug 2026, " + new Date().toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit" }) },
      ],
    };
    setThreads(prev => [newThread, ...prev]);
    setComposeSuccess(true);
    setTimeout(() => {
      setComposeSuccess(false);
      setForm({ type: "", url: "", message: "" });
      setView("inbox");
      setSelected(newThread);
    }, 1500);
  };

  // Thread detail view
  if (selected) {
    return (
      <div className="max-w-3xl space-y-0">
        {/* Toolbar */}
        <div className="flex items-center gap-2 mb-4">
          <button onClick={() => setSelected(null)}
            className="flex items-center gap-1.5 text-slate-600 hover:text-slate-900 text-sm font-medium px-3 py-1.5 rounded-lg hover:bg-slate-100 transition-colors">
            ← Inbox
          </button>
        </div>

        <div className="bg-white rounded-2xl border border-slate-200 overflow-hidden">
          {/* Thread header */}
          <div className="px-6 py-5 border-b border-slate-100">
            <div className="flex items-start justify-between gap-4 flex-wrap">
              <div className="flex-1 min-w-0">
                <h2 className="text-lg font-semibold text-slate-900 leading-snug">{selected.subject}</h2>
                <div className="flex items-center gap-2 mt-2 flex-wrap">
                  <StatusBadge status={selected.status} />
                  <span className="text-slate-400 text-xs">·</span>
                  <span className="text-slate-500 text-xs">{selected.type}</span>
                  {selected.url && (
                    <>
                      <span className="text-slate-400 text-xs">·</span>
                      <span className="text-xs font-mono text-slate-500">{selected.url}</span>
                    </>
                  )}
                </div>
              </div>
            </div>
          </div>

          {/* Messages */}
          <div className="divide-y divide-slate-100">
            {selected.messages.map((msg, i) => (
              <div key={msg.id} className="px-6 py-5">
                {/* Sender row */}
                <div className="flex items-center gap-3 mb-3">
                  <div className={`w-8 h-8 rounded-full flex items-center justify-center text-xs font-bold shrink-0 ${avatarColor(msg.role)}`}>
                    {msg.avatar}
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-sm font-semibold text-slate-800">{msg.from}</span>
                      <span className={`text-xs px-1.5 py-0.5 rounded font-medium
                        ${msg.role === "admin" ? "bg-blue-50 text-[#1e3a5f]" : msg.role === "employer" ? "bg-purple-50 text-purple-700" : "bg-slate-100 text-slate-600"}`}>
                        {roleLabel(msg.role)}
                      </span>
                    </div>
                    <p className="text-xs text-slate-400 mt-0.5">{msg.time}</p>
                  </div>
                  {i === selected.messages.length - 1 && msg.role !== "user" && (
                    <span className="text-xs text-blue-600 bg-blue-50 px-2 py-0.5 rounded-full font-medium shrink-0">Latest reply</span>
                  )}
                </div>

                {/* Body */}
                <div className="ml-11 text-sm text-slate-700 leading-relaxed">
                  {msg.text}
                </div>
              </div>
            ))}
          </div>

          {/* Reply area */}
          <div className="px-6 pb-6 pt-4 border-t border-slate-100">
            {selected.status === "Closed" ? (
              <div className="text-center py-4 text-slate-400 text-sm bg-slate-50 rounded-xl">
                This feedback thread is closed and no longer accepts replies.
              </div>
            ) : (
              <div className="border border-slate-300 rounded-xl overflow-hidden focus-within:border-[#1e3a5f] focus-within:ring-2 focus-within:ring-[#1e3a5f]/10 transition-all">
                <div className="flex items-center gap-2 px-4 py-2.5 bg-slate-50 border-b border-slate-200">
                  <div className="w-6 h-6 rounded-full bg-slate-200 text-slate-700 flex items-center justify-center text-[10px] font-bold">JT</div>
                  <span className="text-xs text-slate-500 font-medium">Reply as John Tan</span>
                </div>
                <textarea
                  value={replyText}
                  onChange={e => setReplyText(e.target.value)}
                  placeholder="Write your reply..."
                  rows={4}
                  className="w-full px-4 py-3 text-sm text-slate-800 placeholder-slate-400 focus:outline-none resize-none"
                />
                <div className="flex items-center justify-between px-4 py-2.5 bg-slate-50 border-t border-slate-200">
                  <span className="text-xs text-slate-400">Press Shift+Enter for new line</span>
                  <button
                    onClick={sendReply}
                    disabled={!replyText.trim()}
                    className="bg-[#1e3a5f] text-white px-5 py-2 rounded-lg text-sm font-semibold hover:bg-[#162d4a] disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
                  >
                    Send Reply
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="max-w-3xl space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-slate-900">Feedback</h2>
          <p className="text-slate-500 text-sm mt-0.5">Report issues and track responses from SafeBrowse support.</p>
        </div>
        <button
          onClick={() => { setView(v => v === "compose" ? "inbox" : "compose"); setComposeSuccess(false); }}
          className="bg-[#1e3a5f] text-white px-4 py-2 rounded-lg text-sm font-semibold hover:bg-[#162d4a] transition-colors"
        >
          {view === "compose" ? "← Back to Inbox" : "+ New Feedback"}
        </button>
      </div>

      {/* Compose form */}
      {view === "compose" && (
        <div className="bg-white rounded-2xl border border-slate-200 p-6">
          <h3 className="font-semibold text-slate-800 mb-4">New Feedback</h3>
          {composeSuccess ? (
            <div className="flex items-center gap-3 p-4 bg-green-50 border border-green-200 rounded-xl">
              <span className="text-green-600 font-bold text-lg">✓</span>
              <p className="text-green-700 text-sm font-medium">Feedback submitted. Redirecting to thread...</p>
            </div>
          ) : (
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-slate-700 mb-1.5">Feedback Type</label>
                <select value={form.type} onChange={e => setForm(f => ({ ...f, type: e.target.value }))}
                  className="w-full px-3.5 py-2.5 border border-slate-300 rounded-lg text-sm bg-white text-slate-700 focus:outline-none focus:border-[#1e3a5f] focus:ring-2 focus:ring-[#1e3a5f]/10">
                  <option value="">Select type...</option>
                  <option>Incorrect Detection</option>
                  <option>False Positive</option>
                  <option>False Negative</option>
                  <option>System Problem</option>
                  <option>Other</option>
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium text-slate-700 mb-1.5">Related URL <span className="text-slate-400 font-normal">(optional)</span></label>
                <input value={form.url} onChange={e => setForm(f => ({ ...f, url: e.target.value }))} placeholder="https://example.com"
                  className="w-full px-3.5 py-2.5 border border-slate-300 rounded-lg text-sm placeholder-slate-400 focus:outline-none focus:border-[#1e3a5f] focus:ring-2 focus:ring-[#1e3a5f]/10 transition-colors" />
              </div>
              <div>
                <label className="block text-sm font-medium text-slate-700 mb-1.5">Message</label>
                <textarea value={form.message} onChange={e => setForm(f => ({ ...f, message: e.target.value }))} rows={5}
                  placeholder="Describe your feedback in detail..."
                  className="w-full px-3.5 py-2.5 border border-slate-300 rounded-lg text-sm placeholder-slate-400 focus:outline-none focus:border-[#1e3a5f] focus:ring-2 focus:ring-[#1e3a5f]/10 transition-colors resize-none" />
              </div>
              <button onClick={submitNew} disabled={!form.type || !form.message.trim()}
                className="bg-[#1e3a5f] text-white px-6 py-2.5 rounded-lg text-sm font-semibold hover:bg-[#162d4a] disabled:opacity-40 disabled:cursor-not-allowed transition-colors">
                Submit Feedback
              </button>
            </div>
          )}
        </div>
      )}

      {/* Inbox */}
      <div className="bg-white rounded-2xl border border-slate-200 overflow-hidden">
        <div className="px-5 py-3.5 border-b border-slate-100 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span className="text-sm font-semibold text-slate-800">Inbox</span>
            {threads.filter(t => t.unread).length > 0 && (
              <span className="bg-[#1e3a5f] text-white text-xs font-bold px-2 py-0.5 rounded-full">
                {threads.filter(t => t.unread).length}
              </span>
            )}
          </div>
          <span className="text-xs text-slate-400">{threads.length} threads</span>
        </div>

        <div className="divide-y divide-slate-100">
          {threads.map(thread => {
            const last = thread.messages[thread.messages.length - 1];
            return (
              <button
                key={thread.id}
                onClick={() => openThread(thread)}
                className={`w-full flex items-start gap-4 px-5 py-4 hover:bg-slate-50 transition-colors text-left ${thread.unread ? "bg-blue-50/40" : ""}`}
              >
                {/* Avatar */}
                <div className={`w-9 h-9 rounded-full flex items-center justify-center text-xs font-bold shrink-0 mt-0.5 ${avatarColor(last.role)}`}>
                  {last.avatar}
                </div>

                {/* Content */}
                <div className="flex-1 min-w-0">
                  <div className="flex items-center justify-between gap-2 mb-1">
                    <div className="flex items-center gap-2 min-w-0">
                      {thread.unread && <div className="w-2 h-2 bg-[#1e3a5f] rounded-full shrink-0" />}
                      <span className={`text-sm truncate ${thread.unread ? "font-bold text-slate-900" : "font-medium text-slate-700"}`}>
                        {thread.subject}
                      </span>
                    </div>
                    <span className="text-xs text-slate-400 shrink-0">{thread.date}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs text-slate-500 truncate">{last.from}: {last.text}</span>
                  </div>
                  <div className="flex items-center gap-2 mt-1.5">
                    <StatusBadge status={thread.status} />
                    <span className="text-xs text-slate-400">{thread.messages.length} {thread.messages.length === 1 ? "message" : "messages"}</span>
                  </div>
                </div>

                <div className="text-slate-300 text-sm shrink-0 mt-1">›</div>
              </button>
            );
          })}

          {threads.length === 0 && (
            <div className="px-5 py-12 text-center text-slate-400 text-sm">No feedback threads yet.</div>
          )}
        </div>
      </div>
    </div>
  );
}
