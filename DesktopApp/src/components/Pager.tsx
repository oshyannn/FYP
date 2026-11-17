import { useEffect, useRef, useState } from "react";

interface Props {
  page: number;
  perPage: number;
  total: number;
  onPage: (p: number) => void;
}

// Fixed pagination bar: First, Previous, current ±3 pages (double-click current page to jump), Next, Last.
export default function Pager({ page, perPage, total, onPage }: Props) {
  const pages = Math.max(1, Math.ceil(total / perPage));
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState(String(page));
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    setDraft(String(page));
    setEditing(false);
  }, [page]);

  useEffect(() => {
    if (editing) inputRef.current?.select();
  }, [editing]);

  if (total <= perPage) return null;

  const start = Math.max(1, page - 3);
  const end = Math.min(pages, page + 3);
  const nums: number[] = [];
  for (let i = start; i <= end; i++) nums.push(i);

  function commit() {
    setEditing(false);
    const parsed = parseInt(draft, 10);
    if (!Number.isNaN(parsed)) {
      const clamped = Math.min(pages, Math.max(1, parsed));
      if (clamped !== page) onPage(clamped);
    }
    setDraft(String(page));
  }

  const navBtn =
    "px-2.5 h-8 rounded-lg text-xs font-medium border border-slate-300 text-slate-600 hover:bg-slate-50 disabled:opacity-40 disabled:hover:bg-transparent transition-colors";

  return (
    <div className="px-5 py-3.5 border-t border-slate-100 flex flex-wrap items-center justify-between gap-3 text-sm text-slate-600">
      <span className="text-xs sm:text-sm text-slate-500">
        Showing <span className="font-medium text-slate-700">{(page - 1) * perPage + 1}</span>–
        <span className="font-medium text-slate-700">{Math.min(page * perPage, total)}</span> of{" "}
        <span className="font-medium text-slate-700">{total.toLocaleString()}</span>
      </span>

      <div className="flex items-center gap-1 flex-wrap">
        <button type="button" onClick={() => onPage(1)} disabled={page <= 1} className={navBtn} title="First page">
          « First
        </button>
        <button type="button" onClick={() => onPage(page - 1)} disabled={page <= 1} className={navBtn} title="Previous page">
          ‹ Prev
        </button>

        {start > 1 && <span className="px-1 text-xs text-slate-400">…</span>}

        {nums.map((p) =>
          p === page ? (
            editing ? (
              <input
                key={p}
                ref={inputRef}
                type="number"
                min={1}
                max={pages}
                value={draft}
                onChange={(e) => setDraft(e.target.value)}
                onBlur={commit}
                onKeyDown={(e) => {
                  if (e.key === "Enter") commit();
                  else if (e.key === "Escape") {
                    setDraft(String(page));
                    setEditing(false);
                  }
                }}
                aria-label="Jump to page"
                className="w-14 h-8 px-1.5 text-center text-sm font-semibold border-2 border-[#1e3a5f] rounded-lg focus:outline-none"
              />
            ) : (
              <button
                key={p}
                type="button"
                onDoubleClick={() => {
                  setDraft(String(page));
                  setEditing(true);
                }}
                title="Double-click to enter a page number"
                aria-current="page"
                className="min-w-8 h-8 px-2.5 rounded-lg text-sm font-semibold bg-[#1e3a5f] text-white shadow-sm cursor-pointer"
              >
                {p}
              </button>
            )
          ) : (
            <button
              key={p}
              type="button"
              onClick={() => onPage(p)}
              className="min-w-8 h-8 px-2.5 rounded-lg text-sm font-medium text-slate-600 hover:bg-slate-100 transition-colors"
            >
              {p}
            </button>
          ),
        )}

        {end < pages && <span className="px-1 text-xs text-slate-400">…</span>}

        <button type="button" onClick={() => onPage(page + 1)} disabled={page >= pages} className={navBtn} title="Next page">
          Next ›
        </button>
        <button type="button" onClick={() => onPage(pages)} disabled={page >= pages} className={navBtn} title="Last page">
          Last »
        </button>
      </div>
    </div>
  );
}
