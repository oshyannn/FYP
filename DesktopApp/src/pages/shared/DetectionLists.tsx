import { useCallback, useEffect, useState } from "react";
import { api, problem } from "../../api";
import Badge from "../../components/Badge";
import Pager from "../../components/Pager";
import { Alert } from "../../components/ui";
import type { Level } from "../../lib/analysis";
import { LIST_TABS } from "../../lib/sites";
import type { ListItem, ListKind } from "../../lib/sites";

const PER_PAGE = 25;
const TONE: Record<Level, "green" | "amber" | "red" | "slate"> = { safe: "green", suspicious: "amber", malicious: "red", unknown: "slate" };

interface Summary {
  [k: string]: { count: number; synced_at?: string | null };
}
interface Check {
  domain: string;
  tranco_rank: number | null;
  top_n: number;
  trusted_top_site: boolean;
  managed_lists: string[];
  admin_threats: { url: string; level: string }[];
  adult: boolean;
  feed_matches: string[];
}

const MANAGED: Record<string, string> = {
  whitelist: "Manual whitelist", not_trusted: "Removed from top sites", blacklist: "Manual blacklist", adult_manual: "Restricted (manual)", shared_hosts: "Shared host",
};

// Every list the detector really uses, readable by users, employers and administrators.
export default function DetectionLists({ onSessionEnd }: { onSessionEnd: () => void }) {
  const [kind, setKind] = useState<ListKind>("trusted");
  const [summary, setSummary] = useState<Summary | null>(null);
  const [items, setItems] = useState<ListItem[]>([]);
  const [total, setTotal] = useState(0);
  const [capped, setCapped] = useState(false);
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState("");
  const [q, setQ] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [domain, setDomain] = useState("");
  const [check, setCheck] = useState<Check | null>(null);

  const tab = LIST_TABS.find((t) => t.kind === kind)!;
  const needSearch = kind === "adult" && q.length < 3;

  useEffect(() => {
    api.get("/api/lists/summary").then((res) => {
      if (res.status === 401) return onSessionEnd();
      if (res.status === 200) setSummary(res.data as Summary);
    });
  }, [onSessionEnd]);

  const load = useCallback(async () => {
    if (needSearch) {
      setItems([]);
      setTotal(0);
      setLoading(false);
      return;
    }
    setLoading(true);
    setError("");
    const res = await api.get(`/api/lists/${kind}?page=${page}&per_page=${PER_PAGE}${q ? `&search=${encodeURIComponent(q)}` : ""}`);
    setLoading(false);
    if (res.status === 401) return onSessionEnd();
    if (res.status !== 200) return setError(problem(res).message);
    setItems(res.data.items as ListItem[]);
    setTotal(res.data.total as number);
    setCapped(!!res.data.capped);
  }, [kind, page, q, needSearch, onSessionEnd]);

  useEffect(() => {
    load();
  }, [load]);

  async function lookup() {
    const d = domain.trim();
    if (!d) return;
    setError("");
    setCheck(null);
    const res = await api.get(`/api/lists/check?domain=${encodeURIComponent(d)}`);
    if (res.status === 401) return onSessionEnd();
    if (res.status !== 200) return setError(problem(res).message);
    setCheck(res.data as Check);
  }

  const cls = "px-3.5 py-2.5 border border-slate-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:border-[#1e3a5f] focus:ring-[#1e3a5f]/10";
  const count = (k: string) => summary?.[k]?.count;

  return (
    <div className="max-w-5xl space-y-5">
      <div>
        <h2 className="text-xl font-bold text-slate-900">Detection Lists</h2>
        <p className="text-slate-500 text-sm mt-0.5">The lists SafeBrowse really uses to judge websites. The same view for everyone.</p>
      </div>
      {error && <Alert kind="error">{error}</Alert>}

      <div className="bg-white rounded-xl border border-slate-200 p-5">
        <h3 className="font-semibold text-slate-800 mb-3">Which lists is a website on?</h3>
        <div className="flex gap-3">
          <input value={domain} onChange={(e) => setDomain(e.target.value)} onKeyDown={(e) => e.key === "Enter" && lookup()} aria-label="Domain" placeholder="example.com" className={`flex-1 ${cls}`} />
          <button onClick={lookup} disabled={!domain.trim()} className="bg-[#1e3a5f] text-white px-5 py-2.5 rounded-lg text-sm font-semibold hover:bg-[#162d4a] disabled:opacity-50">Check</button>
        </div>
        {check && (
          <ul className="mt-3 text-sm text-slate-700 space-y-1">
            <li className="font-mono">{check.domain}</li>
            {check.trusted_top_site && <li>✓ Trusted top site (rank {check.tranco_rank} of top {check.top_n})</li>}
            {!check.trusted_top_site && check.tranco_rank !== null && <li>Top-site list rank {check.tranco_rank}, but not trusted (outside the top {check.top_n} or removed).</li>}
            {check.managed_lists.map((m) => <li key={m}>• {MANAGED[m] ?? m}</li>)}
            {check.admin_threats.map((t) => <li key={t.url} className="text-red-600 break-all">⚠ Administrator-approved threat ({t.level}): {t.url}</li>)}
            {check.adult && <li>• Restricted (adult content)</li>}
            {check.feed_matches.map((u) => <li key={u} className="text-red-600 break-all">⚠ Threat feed: {u}</li>)}
            {!check.trusted_top_site && check.tranco_rank === null && check.managed_lists.length === 0 && check.admin_threats.length === 0 && !check.adult && check.feed_matches.length === 0 && (
              <li className="text-slate-500">On no list. The detector checks it with its other methods.</li>
            )}
          </ul>
        )}
      </div>

      <div className="flex flex-wrap gap-2">
        {LIST_TABS.map((t) => (
          <button
            key={t.kind}
            onClick={() => {
              setKind(t.kind);
              setPage(1);
              setSearch("");
              setQ("");
            }}
            className={`px-4 py-2 rounded-lg text-sm font-medium border ${kind === t.kind ? "bg-[#1e3a5f] text-white border-[#1e3a5f]" : "bg-white text-slate-600 border-slate-300 hover:bg-slate-50"}`}
          >
            {t.label}
            {count(t.kind) !== undefined && <span className="ml-2 opacity-70">{count(t.kind)!.toLocaleString()}</span>}
          </button>
        ))}
      </div>

      <div className="bg-white rounded-xl border border-slate-200 overflow-hidden">
        <div className="px-5 py-4 border-b border-slate-100 flex items-center justify-between gap-4">
          <p className="text-sm text-slate-500">{tab.help}</p>
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                setPage(1);
                setQ(search.trim());
              }
            }}
            aria-label="Search the list"
            placeholder="Search, press Enter"
            className={`w-56 shrink-0 ${cls} py-1.5`}
          />
        </div>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="text-xs text-slate-500 bg-slate-50 border-b border-slate-200">
                {["Entry", "Source", "Detail", "Level"].map((h) => <th key={h} className="text-left px-5 py-3 font-medium">{h}</th>)}
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {items.map((r, i) => (
                <tr key={`${r.item}-${i}`} className="hover:bg-slate-50">
                  <td className="px-5 py-3 text-sm font-mono text-slate-700 break-all">{r.item}</td>
                  <td className="px-5 py-3 text-sm text-slate-600">{r.source}</td>
                  <td className="px-5 py-3 text-sm text-slate-500">{r.detail ?? ""}</td>
                  <td className="px-5 py-3">{r.level && <Badge tone={TONE[r.level]}>{r.level}</Badge>}</td>
                </tr>
              ))}
              {items.length === 0 && (
                <tr>
                  <td colSpan={4} className="px-5 py-10 text-center text-slate-400 text-sm">
                    {needSearch ? "Type at least 3 characters and press Enter to search this list." : loading ? "Loading…" : "Nothing found."}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
        {capped && <p className="px-5 py-2 text-xs text-slate-400 border-t border-slate-100">More than 10,000 matches. Narrow the search.</p>}
        <Pager page={page} perPage={PER_PAGE} total={total} onPage={setPage} />
      </div>
    </div>
  );
}
