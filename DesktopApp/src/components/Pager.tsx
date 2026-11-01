interface Props {
  page: number;
  perPage: number;
  total: number;
  onPage: (p: number) => void;
}

// "Showing 1–10 of 25" with previous / next. Renders nothing when everything fits on one page.
export default function Pager({ page, perPage, total, onPage }: Props) {
  if (total <= perPage) return null;
  const pages = Math.ceil(total / perPage);
  const btn = "px-3 h-8 rounded-lg text-sm font-medium border border-slate-300 text-slate-600 hover:bg-slate-50 disabled:opacity-40 disabled:hover:bg-transparent";
  return (
    <div className="px-5 py-3.5 border-t border-slate-100 flex items-center justify-between text-sm text-slate-600">
      <span>
        Showing {(page - 1) * perPage + 1}–{Math.min(page * perPage, total)} of {total}
      </span>
      <div className="flex items-center gap-2">
        <button onClick={() => onPage(page - 1)} disabled={page <= 1} className={btn}>
          Previous
        </button>
        <span className="text-xs text-slate-500">
          Page {page} of {pages}
        </span>
        <button onClick={() => onPage(page + 1)} disabled={page >= pages} className={btn}>
          Next
        </button>
      </div>
    </div>
  );
}
