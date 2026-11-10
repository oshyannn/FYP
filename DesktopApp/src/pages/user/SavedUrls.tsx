import { useCallback, useEffect, useState } from "react";
import { api, problem } from "../../api";
import ConfirmDialog from "../../components/ConfirmDialog";
import Pager from "../../components/Pager";
import StatusBadge from "../../components/StatusBadge";
import { Alert } from "../../components/ui";
import type { Level } from "../../lib/analysis";
import { scoreClass, shortDate, shortDateTime } from "../../lib/approvals";

interface SavedUrl {
  id: string;
  url: string;
  domain: string;
  title: string | null;
  note: string | null;
  risk_level: Level;
  risk_score: number;
  checked_at: string | null; // null = saved without a verdict
  saved_at: string;
}

const PER_PAGE = 10;

// The desktop bridge only forwards simple query strings, so the characters encodeURIComponent leaves alone are encoded too.
const enc = (s: string) => encodeURIComponent(s).replace(/[!'()*]/g, (c) => "%" + c.charCodeAt(0).toString(16).toUpperCase());

interface Props {
  onSessionEnd: () => void;
}

// The websites the person starred in the browser extension (table saved_urls). Nothing is added here: the star is in the extension.
export default function SavedUrls({ onSessionEnd }: Props) {
  const [items, setItems] = useState<SavedUrl[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [input, setInput] = useState("");
  const [query, setQuery] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busyId, setBusyId] = useState<string | null>(null);
  const [editId, setEditId] = useState<string | null>(null);
  const [noteDraft, setNoteDraft] = useState("");
  const [target, setTarget] = useState<SavedUrl | null>(null);
  const [removing, setRemoving] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    const res = await api.get(`/api/saved-urls?page=${page}&per_page=${PER_PAGE}${query ? `&search=${enc(query)}` : ""}`);
    setLoading(false);
    if (res.status === 401) return onSessionEnd();
    if (res.status !== 200) return setError(problem(res).message);
    setError("");
    setItems(res.data.items as SavedUrl[]);
    setTotal(res.data.total as number);
  }, [page, query]);

  useEffect(() => {
    load();
  }, [load]);

  function search() {
    setNotice("");
    setPage(1);
    setQuery(input.trim());
  }

  const replace = (item: SavedUrl) => setItems((list) => list.map((x) => (x.id === item.id ? item : x)));

  async function rescan(row: SavedUrl) {
    if (busyId) return;
    setBusyId(row.id);
    setError("");
    setNotice("");
    const res = await api.post(`/api/saved-urls/${row.id}/rescan`);
    setBusyId(null);
    if (res.status === 401) return onSessionEnd();
    if (res.status === 200) {
      replace(res.data.item as SavedUrl);
      return setNotice(`${row.domain} was checked again.`);
    }
    setError(res.status === 429 ? "Too many re-scans. Wait a while and try again." : problem(res).message);
  }

  async function saveNote(row: SavedUrl) {
    if (busyId) return;
    setBusyId(row.id);
    setError("");
    const res = await api.patch(`/api/saved-urls/${row.id}`, { note: noteDraft.trim() });
    setBusyId(null);
    if (res.status === 401) return onSessionEnd();
    if (res.status !== 200) return setError(problem(res).message);
    replace(res.data.item as SavedUrl);
    setEditId(null);
  }

  async function remove() {
    if (!target || removing) return;
    setRemoving(true);
    const res = await api.del(`/api/saved-urls/${target.id}`);
    setRemoving(false);
    if (res.status === 401) return onSessionEnd();
    setTarget(null);
    if (res.status !== 200 && res.status !== 404) return setError(problem(res).message);
    if (page > 1 && items.length <= 1) setPage(page - 1);
    else load();
  }

  return (
    <div className="max-w-3xl space-y-5">
      <div>
        <h2 className="text-xl font-bold text-slate-900">Saved URLs</h2>
        <p className="text-slate-500 text-sm mt-0.5">
          Websites you starred with the SafeBrowse browser extension. Open a page in Chrome and press <b>Save this page</b> in the extension to add one.
        </p>
      </div>

      {error && <Alert kind="error">{error}</Alert>}
      {notice && <Alert kind="success">{notice}</Alert>}

      <div className="flex gap-3">
        <input
          value={input}
          maxLength={200}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && search()}
          aria-label="Search saved websites"
          placeholder="Search by address, title or note"
          className="flex-1 px-3.5 py-2.5 border border-slate-300 rounded-lg text-sm placeholder-slate-400 focus:outline-none focus:ring-2 focus:border-[#1e3a5f] focus:ring-[#1e3a5f]/10"
        />
        <button onClick={search} className="bg-[#1e3a5f] text-white px-5 py-2.5 rounded-lg text-sm font-semibold hover:bg-[#162d4a] transition-colors">
          Search
        </button>
      </div>

      <div className="bg-white rounded-xl border border-slate-200 overflow-hidden">
        <div className="px-5 py-4 border-b border-slate-100">
          <h3 className="font-semibold text-slate-800">Your saved websites ({total})</h3>
        </div>
        <ul className="divide-y divide-slate-100">
          {items.map((row) => (
            <li key={row.id} className="px-5 py-4">
              <div className="flex items-start justify-between gap-4">
                <div className="min-w-0">
                  <p className="text-sm font-semibold text-slate-800 break-words">{row.title || row.domain}</p>
                  <p className="text-xs font-mono text-slate-500 break-all mt-0.5">{row.url}</p>
                  <p className="text-xs text-slate-400 mt-1">
                    Saved {shortDate(row.saved_at)}
                    {row.checked_at ? ` · checked ${shortDateTime(row.checked_at)}` : " · not checked yet"}
                  </p>
                </div>
                <div className="shrink-0 text-right">
                  <StatusBadge level={row.checked_at ? row.risk_level : "unknown"} />
                  {row.checked_at && <p className={`text-sm font-semibold mt-1 ${scoreClass(row.risk_score)}`}>{Math.round(row.risk_score)}/100</p>}
                </div>
              </div>

              {editId === row.id ? (
                <div className="mt-3 flex gap-2">
                  <input
                    value={noteDraft}
                    maxLength={500}
                    autoFocus
                    onChange={(e) => setNoteDraft(e.target.value)}
                    onKeyDown={(e) => e.key === "Enter" && saveNote(row)}
                    aria-label="Note"
                    placeholder="Add a note"
                    className="flex-1 px-3 py-2 border border-slate-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:border-[#1e3a5f] focus:ring-[#1e3a5f]/10"
                  />
                  <button
                    onClick={() => saveNote(row)}
                    disabled={busyId === row.id}
                    className="bg-[#1e3a5f] text-white px-4 py-2 rounded-lg text-sm font-semibold disabled:opacity-50"
                  >
                    Save
                  </button>
                  <button onClick={() => setEditId(null)} className="border border-slate-300 text-slate-600 px-4 py-2 rounded-lg text-sm font-medium hover:bg-slate-50">
                    Cancel
                  </button>
                </div>
              ) : (
                row.note && <p className="text-sm text-slate-600 mt-2 break-words">Note: {row.note}</p>
              )}

              <div className="mt-3 flex gap-4 text-sm font-medium">
                <button onClick={() => rescan(row)} disabled={busyId === row.id} className="text-[#1e3a5f] hover:underline disabled:opacity-50">
                  {busyId === row.id ? "Checking…" : "Scan again"}
                </button>
                <button
                  onClick={() => {
                    setEditId(row.id);
                    setNoteDraft(row.note ?? "");
                  }}
                  className="text-slate-600 hover:underline"
                >
                  {row.note ? "Edit note" : "Add note"}
                </button>
                <button onClick={() => setTarget(row)} className="text-red-500 hover:underline">
                  Remove
                </button>
              </div>
            </li>
          ))}
          {items.length === 0 && (
            <li className="px-5 py-10 text-center text-slate-400 text-sm">
              {loading ? "Loading…" : query ? "No saved website matches your search." : "Nothing saved yet. Use the star in the browser extension."}
            </li>
          )}
        </ul>
        <Pager page={page} perPage={PER_PAGE} total={total} onPage={setPage} />
      </div>

      {target && (
        <ConfirmDialog title="Remove saved website?" tone="red" confirmLabel="Remove" busy={removing} onConfirm={remove} onCancel={() => setTarget(null)}>
          <p className="font-mono mb-1 break-all">{target.url}</p>
          <p>It will no longer be in your saved list.</p>
        </ConfirmDialog>
      )}
    </div>
  );
}
