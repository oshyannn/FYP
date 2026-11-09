import { useCallback, useEffect, useState } from "react";
import { api, problem } from "../../api";
import Badge from "../../components/Badge";
import ConfirmDialog from "../../components/ConfirmDialog";
import Pager from "../../components/Pager";
import { Alert } from "../../components/ui";
import { LEVEL_STYLE } from "../../lib/analysis";
import type { Level } from "../../lib/analysis";
import type { SavedUrl } from "../../lib/sites";

const PER_PAGE = 10;
const TONE: Record<Level, "green" | "amber" | "red" | "slate"> = { safe: "green", suspicious: "amber", malicious: "red", unknown: "slate" };
const day = (iso: string | null) => (iso ? new Date(iso).toLocaleDateString(undefined, { day: "numeric", month: "short", year: "numeric" }) : "-");

// Websites the person starred in the browser extension (or here). The verdict can be refreshed at any time.
export default function SavedUrls({ onSessionEnd }: { onSessionEnd: () => void }) {
  const [items, setItems] = useState<SavedUrl[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState("");
  const [q, setQ] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [input, setInput] = useState("");
  const [adding, setAdding] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const [target, setTarget] = useState<SavedUrl | null>(null);
  const [editing, setEditing] = useState<string | null>(null);
  const [noteText, setNoteText] = useState("");

  const load = useCallback(async () => {
    setLoading(true);
    const res = await api.get(`/api/saved-urls?page=${page}&per_page=${PER_PAGE}${q ? `&search=${encodeURIComponent(q)}` : ""}`);
    setLoading(false);
    if (res.status === 401) return onSessionEnd();
    if (res.status !== 200) return setError(problem(res).message);
    setItems(res.data.items as SavedUrl[]);
    setTotal(res.data.total as number);
  }, [page, q, onSessionEnd]);

  useEffect(() => {
    load();
  }, [load]);

  async function add() {
    const url = input.trim();
    if (!url || adding) return;
    setAdding(true);
    setError("");
    setNotice("");
    const res = await api.post("/api/saved-urls", { url });
    setAdding(false);
    if (res.status === 401) return onSessionEnd();
    if (res.status === 201 || res.status === 200) {
      setInput("");
      setNotice(res.status === 201 ? "Website saved." : "Already saved.");
      if (page !== 1) setPage(1);
      else load();
      return;
    }
    setError(problem(res).message);
  }

  async function rescan(s: SavedUrl) {
    setBusy(s.id);
    setError("");
    const res = await api.post(`/api/saved-urls/${s.id}/rescan`);
    setBusy(null);
    if (res.status === 401) return onSessionEnd();
    if (res.status !== 200) return setError(problem(res).message);
    const item = res.data.item as SavedUrl;
    setItems((list) => list.map((x) => (x.id === item.id ? item : x)));
  }

  async function saveNote(s: SavedUrl) {
    const res = await api.patch(`/api/saved-urls/${s.id}`, { note: noteText.trim() || null });
    if (res.status === 401) return onSessionEnd();
    if (res.status !== 200) return setError(problem(res).message);
    const item = res.data.item as SavedUrl;
    setItems((list) => list.map((x) => (x.id === item.id ? item : x)));
    setEditing(null);
  }

  async function remove() {
    if (!target) return;
    setBusy(target.id);
    const res = await api.del(`/api/saved-urls/${target.id}`);
    setBusy(null);
    if (res.status === 401) return onSessionEnd();
    setTarget(null);
    if (res.status !== 200 && res.status !== 404) return setError(problem(res).message);
    if (page > 1 && items.length <= 1) setPage(page - 1);
    else load();
  }

  const cls = "px-3.5 py-2.5 border border-slate-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:border-[#1e3a5f] focus:ring-[#1e3a5f]/10";

  return (
    <div className="max-w-4xl space-y-5">
      <div>
        <h2 className="text-xl font-bold text-slate-900">Saved URLs</h2>
        <p className="text-slate-500 text-sm mt-0.5">Websites you starred in the browser extension. Star a page there to keep it here.</p>
      </div>
      {error && <Alert kind="error">{error}</Alert>}
      {notice && <Alert kind="success">{notice}</Alert>}

      <div className="bg-white rounded-xl border border-slate-200 p-5 flex gap-3">
        <input
          value={input}
          maxLength={2048}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && add()}
          aria-label="Website to save"
          placeholder="https://example.com/page"
          className={`flex-1 ${cls}`}
        />
        <button onClick={add} disabled={adding || !input.trim()} className="bg-[#1e3a5f] text-white px-5 py-2.5 rounded-lg text-sm font-semibold hover:bg-[#162d4a] disabled:opacity-50">
          {adding ? "Saving…" : "★ Save"}
        </button>
      </div>

      <div className="bg-white rounded-xl border border-slate-200 overflow-hidden">
        <div className="px-5 py-4 border-b border-slate-100 flex items-center justify-between gap-3">
          <h3 className="font-semibold text-slate-800">Saved ({total})</h3>
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                setPage(1);
                setQ(search.trim());
              }
            }}
            aria-label="Search saved websites"
            placeholder="Search, press Enter"
            className={`w-56 ${cls} py-1.5`}
          />
        </div>
        <ul className="divide-y divide-slate-100">
          {items.map((s) => (
            <li key={s.id} className="px-5 py-4">
              <div className="flex items-start justify-between gap-4">
                <div className="min-w-0">
                  <p className="text-sm font-semibold text-slate-800 truncate">{s.title || s.domain}</p>
                  <p className="text-xs font-mono text-slate-500 break-all">{s.url}</p>
                  <p className="text-xs text-slate-400 mt-1">
                    Saved {day(s.saved_at)} · checked {day(s.checked_at)}
                  </p>
                </div>
                <div className="text-right shrink-0">
                  <Badge tone={TONE[s.risk_level]}>{LEVEL_STYLE[s.risk_level].label}</Badge>
                </div>
              </div>
              {editing === s.id ? (
                <div className="mt-2 flex gap-2">
                  <input value={noteText} maxLength={500} onChange={(e) => setNoteText(e.target.value)} aria-label="Note" placeholder="Note" className={`flex-1 ${cls} py-1.5`} />
                  <button onClick={() => saveNote(s)} className="text-sm font-medium text-[#1e3a5f] hover:underline">Save</button>
                  <button onClick={() => setEditing(null)} className="text-sm text-slate-500 hover:underline">Cancel</button>
                </div>
              ) : (
                s.note && <p className="text-sm text-slate-600 mt-2">{s.note}</p>
              )}
              <div className="mt-2 flex gap-4 text-sm font-medium">
                <button onClick={() => rescan(s)} disabled={busy === s.id} className="text-[#1e3a5f] hover:underline disabled:opacity-50">
                  {busy === s.id ? "Checking…" : "Re-check"}
                </button>
                <button
                  onClick={() => {
                    setEditing(s.id);
                    setNoteText(s.note ?? "");
                  }}
                  className="text-slate-600 hover:underline"
                >
                  {s.note ? "Edit note" : "Add note"}
                </button>
                <button onClick={() => setTarget(s)} className="text-red-500 hover:underline">Remove</button>
              </div>
            </li>
          ))}
          {items.length === 0 && <li className="px-5 py-10 text-center text-slate-400 text-sm">{loading ? "Loading…" : "No saved websites."}</li>}
        </ul>
        <Pager page={page} perPage={PER_PAGE} total={total} onPage={setPage} />
      </div>

      {target && (
        <ConfirmDialog title="Remove saved website?" tone="red" confirmLabel="Remove" busy={busy === target.id} onConfirm={remove} onCancel={() => setTarget(null)}>
          <p className="font-mono break-all">{target.url}</p>
        </ConfirmDialog>
      )}
    </div>
  );
}
