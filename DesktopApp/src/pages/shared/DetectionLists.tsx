import { useCallback, useEffect, useState } from "react";
import { api, problem } from "../../api";
import Badge from "../../components/Badge";
import ConfirmDialog from "../../components/ConfirmDialog";
import EmployerReasonModal from "../../components/EmployerReasonModal";
import Pager from "../../components/Pager";
import StatusBadge from "../../components/StatusBadge";
import { Alert } from "../../components/ui";
import type { StaffRole } from "../../lib/admin";
import type { Level } from "../../lib/analysis";
import { LIST_TABS } from "../../lib/sites";
import type { ListItem, ListKind } from "../../lib/sites";
import { THREAT_TYPE_OPTIONS, threatTypeLabel, threatTypeTone } from "../../lib/threats";
import type { ThreatItem, ThreatStats } from "../../lib/threats";
import { validateUrlInput } from "../../lib/urlValidation";
import ThreatFormModal from "../staff/approval/ThreatFormModal";

const PER_PAGE = 25;
const THREATS_PER_PAGE = 10;
const TONE: Record<Level, "green" | "amber" | "red" | "slate"> = { safe: "green", suspicious: "amber", malicious: "red", unknown: "slate" };
const selectCls =
  "px-3 py-2 border border-slate-300 rounded-lg text-sm bg-white text-slate-700 focus:outline-none focus:border-[#1e3a5f]";

interface Summary {
  [k: string]: { count: number; admin_approved?: number; synced_at?: string | null };
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
  whitelist: "Manual whitelist",
  not_trusted: "Removed from top sites",
  blacklist: "Manual blacklist",
  adult_manual: "Restricted (manual)",
  shared_hosts: "Shared host",
};

type CentralTab = "threats" | ListKind;

// Centralized Detection Lists: active Threat URLs (with filter/search/sort & staff CRUD) + all detector lists.
export default function DetectionLists({ staffRole, onSessionEnd }: { staffRole?: StaffRole; onSessionEnd: () => void }) {
  const isStaff = !!staffRole;
  const isEmployer = staffRole === "employer";

  const [tabKey, setTabKey] = useState<CentralTab>("threats");
  const [summary, setSummary] = useState<Summary | null>(null);

  // Threat URLs state
  const [threats, setThreats] = useState<ThreatItem[]>([]);
  const [threatStats, setThreatStats] = useState<ThreatStats | null>(null);
  const [threatTotal, setThreatTotal] = useState(0);
  const [threatPage, setThreatPage] = useState(1);
  const [tSearch, setTSearch] = useState("");
  const [tQ, setTQ] = useState("");
  const [tType, setTType] = useState("");
  const [tSeverity, setTSeverity] = useState("");
  const [tSort, setTSort] = useState("newest");
  const [showAdd, setShowAdd] = useState(false);
  const [editing, setEditing] = useState<ThreatItem | null>(null);
  const [deleting, setDeleting] = useState<ThreatItem | null>(null);
  const [busy, setBusy] = useState(false);

  // Detector lists state
  const [items, setItems] = useState<ListItem[]>([]);
  const [total, setTotal] = useState(0);
  const [capped, setCapped] = useState(false);
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState("");
  const [q, setQ] = useState("");

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  // Lookup state
  const [domain, setDomain] = useState("");
  const [domainErr, setDomainErr] = useState("");
  const [check, setCheck] = useState<Check | null>(null);

  useEffect(() => {
    const t = window.setTimeout(() => {
      setTQ(tSearch.trim());
      setThreatPage(1);
    }, 300);
    return () => window.clearTimeout(t);
  }, [tSearch]);

  const loadSummary = useCallback(() => {
    api.get("/api/lists/summary").then((res) => {
      if (res.status === 401) return onSessionEnd();
      if (res.status === 200) setSummary(res.data as Summary);
    });
  }, [onSessionEnd]);

  useEffect(() => {
    loadSummary();
  }, [loadSummary]);

  const loadThreats = useCallback(async () => {
    if (tabKey !== "threats") return;
    setLoading(true);
    setError("");
    const qs = new URLSearchParams({
      status: "active",
      page: String(threatPage),
      per_page: String(THREATS_PER_PAGE),
      sort: tSort,
    });
    if (tQ) qs.set("search", tQ);
    if (tType) qs.set("type", tType);
    if (tSeverity) qs.set("risk_level", tSeverity);
    const res = await api.get(`/api/threats?${qs.toString()}`);
    setLoading(false);
    if (res.status === 401) return onSessionEnd();
    if (res.status !== 200) return setError(problem(res).message);
    setThreats(res.data.threats as ThreatItem[]);
    setThreatTotal(res.data.total as number);
    setThreatStats(res.data.stats as ThreatStats);
  }, [tabKey, threatPage, tQ, tType, tSeverity, tSort, onSessionEnd]);

  const needSearch = tabKey === "adult" && q.length < 3;

  const loadList = useCallback(async () => {
    if (tabKey === "threats") return;
    if (needSearch) {
      setItems([]);
      setTotal(0);
      setLoading(false);
      return;
    }
    setLoading(true);
    setError("");
    const res = await api.get(`/api/lists/${tabKey}?page=${page}&per_page=${PER_PAGE}${q ? `&search=${encodeURIComponent(q)}` : ""}`);
    setLoading(false);
    if (res.status === 401) return onSessionEnd();
    if (res.status !== 200) return setError(problem(res).message);
    setItems(res.data.items as ListItem[]);
    setTotal(res.data.total as number);
    setCapped(!!res.data.capped);
  }, [tabKey, page, q, needSearch, onSessionEnd]);

  useEffect(() => {
    if (tabKey === "threats") loadThreats();
    else loadList();
  }, [tabKey, loadThreats, loadList]);

  async function lookup() {
    const parsed = validateUrlInput(domain);
    if (!parsed.valid) {
      setDomainErr(parsed.error);
      return;
    }
    setDomainErr("");
    setError("");
    setCheck(null);
    const res = await api.get(`/api/lists/check?domain=${encodeURIComponent(parsed.host)}`);
    if (res.status === 401) return onSessionEnd();
    if (res.status !== 200) return setError(problem(res).message);
    setCheck(res.data as Check);
  }

  async function confirmDelete(reasonText?: string) {
    if (!deleting || busy) return;
    setBusy(true);
    setError("");
    const res = await api.del(`/api/staff/threats/${deleting.id}`, reasonText ? { reason: reasonText } : undefined);
    setBusy(false);
    if (res.status === 401) return onSessionEnd();
    setDeleting(null);
    if (res.status !== 200) return setError(problem(res).message);
    setNotice(`${deleting.url} deleted from the Detection List.`);
    loadThreats();
    loadSummary();
  }

  const cls = "px-3.5 py-2.5 border border-slate-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:border-[#1e3a5f] focus:ring-[#1e3a5f]/10";
  const count = (k: string) => summary?.[k]?.count;
  const activeTabMeta = LIST_TABS.find((t) => t.kind === tabKey);

  return (
    <div className="max-w-6xl space-y-5">
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h2 className="text-xl font-bold text-slate-900">Detection Lists</h2>
          <p className="text-slate-500 text-sm mt-0.5">
            Centralized view of all active threat URLs, trusted sites, threat feeds, and domain lists used by SafeBrowse.
          </p>
        </div>
        {isStaff && (
          <button
            type="button"
            onClick={() => {
              setNotice("");
              setShowAdd(true);
            }}
            className="shrink-0 bg-[#1e3a5f] text-white px-4 py-2.5 rounded-lg text-sm font-semibold hover:bg-[#162d4a] transition-colors flex items-center gap-2"
          >
            <span className="text-base leading-none">+</span> Add Threat URL
          </button>
        )}
      </div>

      {error && <Alert kind="error">{error}</Alert>}
      {notice && <Alert kind="success">{notice}</Alert>}

      <div className="bg-white rounded-xl border border-slate-200 p-5">
        <h3 className="font-semibold text-slate-800 mb-3">Check Website List Status</h3>
        <div className="flex gap-3">
          <input
            value={domain}
            onChange={(e) => {
              setDomain(e.target.value);
              setDomainErr("");
            }}
            onKeyDown={(e) => e.key === "Enter" && lookup()}
            aria-label="Domain or URL"
            placeholder="example.com or https://example.com/page"
            className={`flex-1 ${cls} ${domainErr ? "border-red-400" : ""}`}
          />
          <button
            type="button"
            onClick={lookup}
            disabled={!domain.trim()}
            className="bg-[#1e3a5f] text-white px-5 py-2.5 rounded-lg text-sm font-semibold hover:bg-[#162d4a] disabled:opacity-50"
          >
            Check
          </button>
        </div>
        {domainErr && <p className="text-red-500 text-xs mt-1.5">{domainErr}</p>}
        {check && (
          <ul className="mt-3 text-sm text-slate-700 space-y-1">
            <li className="font-mono font-semibold">{check.domain}</li>
            {check.trusted_top_site && <li>✓ Trusted top site (rank {check.tranco_rank} of top {check.top_n})</li>}
            {!check.trusted_top_site && check.tranco_rank !== null && (
              <li>Top-site list rank {check.tranco_rank}, not trusted (outside top {check.top_n} or excluded).</li>
            )}
            {check.managed_lists.map((m) => (
              <li key={m}>• {MANAGED[m] ?? m}</li>
            ))}
            {check.admin_threats.map((t) => (
              <li key={t.url} className="text-red-600 break-all">
                ⚠ Approved threat ({t.level}): {t.url}
              </li>
            ))}
            {check.adult && <li>• Restricted (adult content)</li>}
            {check.feed_matches.map((u) => (
              <li key={u} className="text-red-600 break-all">
                ⚠ Threat feed: {u}
              </li>
            ))}
            {!check.trusted_top_site &&
              check.tranco_rank === null &&
              check.managed_lists.length === 0 &&
              check.admin_threats.length === 0 &&
              !check.adult &&
              check.feed_matches.length === 0 && (
                <li className="text-slate-500">Not listed. SafeBrowse evaluates it dynamically during scans.</li>
              )}
          </ul>
        )}
      </div>

      <div className="flex flex-wrap gap-2">
        <button
          type="button"
          onClick={() => setTabKey("threats")}
          className={`px-4 py-2 rounded-lg text-sm font-medium border transition-colors ${
            tabKey === "threats" ? "bg-[#1e3a5f] text-white border-[#1e3a5f]" : "bg-white text-slate-600 border-slate-300 hover:bg-slate-50"
          }`}
        >
          Threat URLs
          {(threatStats?.total ?? summary?.blocked?.admin_approved) !== undefined && (
            <span className="ml-2 opacity-75">
              {(threatStats?.total ?? summary?.blocked?.admin_approved ?? 0).toLocaleString()}
            </span>
          )}
        </button>
        {LIST_TABS.map((t) => (
          <button
            key={t.kind}
            type="button"
            onClick={() => {
              setTabKey(t.kind);
              setPage(1);
              setSearch("");
              setQ("");
            }}
            className={`px-4 py-2 rounded-lg text-sm font-medium border transition-colors ${
              tabKey === t.kind ? "bg-[#1e3a5f] text-white border-[#1e3a5f]" : "bg-white text-slate-600 border-slate-300 hover:bg-slate-50"
            }`}
          >
            {t.label}
            {count(t.kind) !== undefined && <span className="ml-2 opacity-75">{count(t.kind)!.toLocaleString()}</span>}
          </button>
        ))}
      </div>

      {tabKey === "threats" ? (
        <div className="space-y-4">
          <div className="bg-white rounded-xl border border-slate-200 p-4 flex flex-wrap gap-3 items-center">
            <input
              value={tSearch}
              onChange={(e) => setTSearch(e.target.value)}
              maxLength={200}
              aria-label="Search threat URL"
              placeholder="Search threat URL or domain..."
              className="flex-1 min-w-48 px-3.5 py-2 border border-slate-300 rounded-lg text-sm placeholder-slate-400 focus:outline-none focus:border-[#1e3a5f] focus:ring-2 focus:ring-[#1e3a5f]/10"
            />
            <select value={tType} onChange={(e) => { setTType(e.target.value); setThreatPage(1); }} aria-label="Filter by category" className={selectCls}>
              <option value="">All Categories</option>
              {THREAT_TYPE_OPTIONS.map(([v, l]) => (
                <option key={v} value={v}>{l}</option>
              ))}
            </select>
            <select value={tSeverity} onChange={(e) => { setTSeverity(e.target.value); setThreatPage(1); }} aria-label="Filter by severity" className={selectCls}>
              <option value="">All Severities</option>
              <option value="malicious">Malicious</option>
              <option value="suspicious">Suspicious</option>
            </select>
            <select value={tSort} onChange={(e) => { setTSort(e.target.value); setThreatPage(1); }} aria-label="Sort order" className={selectCls}>
              <option value="newest">Newest First</option>
              <option value="oldest">Oldest First</option>
              <option value="detections">Most Detected</option>
              <option value="url">URL (A–Z)</option>
            </select>
            <button
              type="button"
              onClick={() => {
                setTSearch("");
                setTQ("");
                setTType("");
                setTSeverity("");
                setTSort("newest");
                setThreatPage(1);
              }}
              className="px-3.5 py-2 border border-slate-300 rounded-lg text-sm text-slate-600 hover:bg-slate-50"
            >
              Reset
            </button>
          </div>

          <div className="bg-white rounded-xl border border-slate-200 overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="text-xs text-slate-500 bg-slate-50 border-b border-slate-200">
                    {["URL", "Category", "Severity", "Detections", "Last Updated", ...(isStaff ? ["Actions"] : [])].map((h) => (
                      <th key={h} className="text-left px-5 py-3 font-medium whitespace-nowrap">
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {threats.map((r) => (
                    <tr key={r.id} className="hover:bg-slate-50 transition-colors">
                      <td className="px-5 py-3.5 text-sm font-mono text-slate-700 max-w-xs truncate" title={r.url}>
                        {r.url}
                      </td>
                      <td className="px-5 py-3.5">
                        <Badge tone={threatTypeTone(r.threat_type)}>{threatTypeLabel(r.threat_type)}</Badge>
                      </td>
                      <td className="px-5 py-3.5">
                        <StatusBadge level={r.risk_level} />
                      </td>
                      <td className="px-5 py-3.5 text-sm text-slate-600">{r.detection_count}</td>
                      <td className="px-5 py-3.5 text-sm text-slate-500 whitespace-nowrap">
                        {new Date(r.last_verified_at).toLocaleDateString()}
                      </td>
                      {isStaff && (
                        <td className="px-5 py-3.5">
                          <div className="flex items-center gap-3 whitespace-nowrap">
                            <button
                              type="button"
                              onClick={() => {
                                setNotice("");
                                setEditing(r);
                              }}
                              className="text-[#1e3a5f] text-sm font-medium hover:underline"
                            >
                              Modify
                            </button>
                            <button
                              type="button"
                              onClick={() => {
                                setNotice("");
                                setDeleting(r);
                              }}
                              className="text-red-500 text-sm font-medium hover:underline"
                            >
                              Delete
                            </button>
                          </div>
                        </td>
                      )}
                    </tr>
                  ))}
                  {threats.length === 0 && (
                    <tr>
                      <td colSpan={isStaff ? 6 : 5} className="px-5 py-10 text-center text-slate-400 text-sm">
                        {loading ? "Loading…" : "No active threat URLs found."}
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
            <Pager page={threatPage} perPage={THREATS_PER_PAGE} total={threatTotal} onPage={setThreatPage} />
          </div>
        </div>
      ) : (
        <div className="bg-white rounded-xl border border-slate-200 overflow-hidden">
          <div className="px-5 py-4 border-b border-slate-100 flex flex-wrap items-center justify-between gap-4">
            <p className="text-sm text-slate-500">{activeTabMeta?.help}</p>
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
                  {["Entry", "Source", "Detail", "Level"].map((h) => (
                    <th key={h} className="text-left px-5 py-3 font-medium">
                      {h}
                    </th>
                  ))}
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
      )}

      {showAdd && staffRole && (
        <ThreatFormModal
          role={staffRole}
          onClose={() => setShowAdd(false)}
          onSessionEnd={onSessionEnd}
          onSaved={(msg) => {
            setShowAdd(false);
            setNotice(msg);
            loadThreats();
            loadSummary();
          }}
        />
      )}

      {editing && staffRole && (
        <ThreatFormModal
          role={staffRole}
          existing={editing}
          onClose={() => setEditing(null)}
          onSessionEnd={onSessionEnd}
          onSaved={(msg) => {
            setEditing(null);
            setNotice(msg);
            loadThreats();
            loadSummary();
          }}
        />
      )}

      {deleting && isEmployer ? (
        <EmployerReasonModal
          title="Delete Threat URL"
          subtitle={deleting.url}
          description="This URL will be permanently removed from the Detection List."
          tone="red"
          confirmLabel="Delete"
          busy={busy}
          onConfirm={(r) => confirmDelete(r)}
          onCancel={() => setDeleting(null)}
        />
      ) : deleting ? (
        <ConfirmDialog
          title="Delete Threat URL?"
          tone="red"
          confirmLabel="Delete"
          busy={busy}
          onConfirm={() => confirmDelete()}
          onCancel={() => setDeleting(null)}
        >
          <p className="font-mono mb-1 break-all">{deleting.url}</p>
          <p>This entry will be permanently removed from the Detection List.</p>
        </ConfirmDialog>
      ) : null}
    </div>
  );
}
