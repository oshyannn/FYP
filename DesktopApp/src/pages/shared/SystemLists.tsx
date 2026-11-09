import { useCallback, useEffect, useState } from "react";
import { api, problem } from "../../api";
import Badge from "../../components/Badge";
import ConfirmDialog from "../../components/ConfirmDialog";
import Pager from "../../components/Pager";
import { Alert } from "../../components/ui";

type ListType = "whitelist" | "not_trusted" | "blacklist" | "adult_manual";
interface Entry {
  id: string;
  type: ListType;
  domain: string;
  note: string | null;
  active: boolean;
  added_at: string;
  added_by: string | null;
}
interface Lookup {
  domain: string;
  tranco_rank: number | null;
  tranco_top_n: number;
  trusted_by_tranco: boolean;
  blacklisted: boolean;
  active_in: string[];
  switched_off_in: string[];
}

const TABS: { type: ListType; label: string; help: string }[] = [
  { type: "whitelist", label: "Whitelist", help: "Always trusted by the detector for every user (unless an administrator-approved threat says otherwise)." },
  { type: "not_trusted", label: "Not trusted", help: "Takes a popular (top-sites) website off the trusted list, so it is checked like any other site. Use this when a big site is abused." },
  { type: "blacklist", label: "Blacklist", help: "Always blocked as malicious, the whole domain and its subdomains." },
  { type: "adult_manual", label: "Restricted (manual)", help: "Adds a domain to the restricted (adult content) list." },
];
const PER_PAGE = 15;
const day = (iso: string) => new Date(iso).toLocaleDateString(undefined, { day: "numeric", month: "short", year: "numeric" });

// The detector's own lists. Employers can read them; administrators add and switch entries off. The detector reloads at once.
export default function SystemLists({ role, onSessionEnd }: { role: "employer" | "admin"; onSessionEnd: () => void }) {
  const admin = role === "admin";
  const [type, setType] = useState<ListType>("blacklist");
  const [entries, setEntries] = useState<Entry[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState("");
  const [q, setQ] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [domain, setDomain] = useState("");
  const [note, setNote] = useState("");
  const [fieldError, setFieldError] = useState("");
  const [busy, setBusy] = useState(false);
  const [target, setTarget] = useState<Entry | null>(null);
  const [confirmAdd, setConfirmAdd] = useState(false);
  const [look, setLook] = useState("");
  const [info, setInfo] = useState<Lookup | null>(null);

  const tab = TABS.find((t) => t.type === type)!;

  const load = useCallback(async () => {
    setLoading(true);
    const res = await api.get(`/api/staff/system-lists?type=${type}&page=${page}&per_page=${PER_PAGE}${q ? `&search=${encodeURIComponent(q)}` : ""}`);
    setLoading(false);
    if (res.status === 401) return onSessionEnd();
    if (res.status !== 200) return setError(problem(res).message);
    setEntries(res.data.entries as Entry[]);
    setTotal(res.data.total as number);
  }, [type, page, q, onSessionEnd]);

  useEffect(() => {
    load();
  }, [load]);

  async function add() {
    setConfirmAdd(false);
    setBusy(true);
    setError("");
    setNotice("");
    setFieldError("");
    const res = await api.post("/api/staff/system-lists", { type, domain: domain.trim(), note: note.trim() || undefined });
    setBusy(false);
    if (res.status === 401) return onSessionEnd();
    if (res.status === 201) {
      setNotice(`${res.data.added.domain} added to ${tab.label}. The detector uses it now.`);
      setDomain("");
      setNote("");
      if (page !== 1) setPage(1);
      else load();
      return;
    }
    const p = problem(res);
    if (res.status === 400 || res.status === 409) setFieldError(p.message);
    else setError(p.message);
  }

  async function remove() {
    if (!target) return;
    setBusy(true);
    const res = await api.del(`/api/staff/system-lists/${target.id}`);
    setBusy(false);
    setTarget(null);
    if (res.status === 401) return onSessionEnd();
    if (res.status !== 200 && res.status !== 404) return setError(problem(res).message);
    setNotice("Entry switched off. The detector uses the change now.");
    if (page > 1 && entries.length <= 1) setPage(page - 1);
    else load();
  }

  async function lookup() {
    const d = look.trim();
    if (!d) return;
    setInfo(null);
    setError("");
    const res = await api.get(`/api/staff/system-lists/lookup?domain=${encodeURIComponent(d)}`);
    if (res.status === 401) return onSessionEnd();
    if (res.status !== 200) return setError(problem(res).message);
    setInfo(res.data as Lookup);
  }

  const cls = "px-3.5 py-2.5 border border-slate-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:border-[#1e3a5f] focus:ring-[#1e3a5f]/10";

  return (
    <div className="max-w-4xl space-y-5">
      <div>
        <h2 className="text-xl font-bold text-slate-900">Detection Rules</h2>
        <p className="text-slate-500 text-sm mt-0.5">
          {admin ? "Manage the lists the detector uses for everyone. Changes apply immediately." : "The detector's own lists. Only an administrator can change them."}
        </p>
      </div>
      {error && <Alert kind="error">{error}</Alert>}
      {notice && <Alert kind="success">{notice}</Alert>}

      <div className="bg-white rounded-xl border border-slate-200 p-5">
        <h3 className="font-semibold text-slate-800 mb-3">Why is a website trusted or not?</h3>
        <div className="flex gap-3">
          <input value={look} onChange={(e) => setLook(e.target.value)} onKeyDown={(e) => e.key === "Enter" && lookup()} aria-label="Domain" placeholder="example.com" className={`flex-1 ${cls}`} />
          <button onClick={lookup} disabled={!look.trim()} className="bg-[#1e3a5f] text-white px-5 py-2.5 rounded-lg text-sm font-semibold hover:bg-[#162d4a] disabled:opacity-50">Check</button>
        </div>
        {info && (
          <ul className="mt-3 text-sm text-slate-700 space-y-1">
            <li className="font-mono">{info.domain}</li>
            <li>{info.tranco_rank === null ? "Not in the top-sites list." : `Top-sites rank ${info.tranco_rank} (trusted up to ${info.tranco_top_n}).`}</li>
            <li>{info.trusted_by_tranco ? "✓ Trusted because of its top-site rank." : "Not trusted through the top-sites list."}</li>
            {info.blacklisted && <li className="text-red-600">⚠ On the blacklist.</li>}
            {info.active_in.length > 0 && <li>Active in: {info.active_in.join(", ")}</li>}
            {info.switched_off_in.length > 0 && <li className="text-slate-500">Switched off in: {info.switched_off_in.join(", ")}</li>}
          </ul>
        )}
      </div>

      <div className="flex flex-wrap gap-2">
        {TABS.map((t) => (
          <button
            key={t.type}
            onClick={() => {
              setType(t.type);
              setPage(1);
              setSearch("");
              setQ("");
              setNotice("");
              setFieldError("");
            }}
            className={`px-4 py-2 rounded-lg text-sm font-medium border ${type === t.type ? "bg-[#1e3a5f] text-white border-[#1e3a5f]" : "bg-white text-slate-600 border-slate-300 hover:bg-slate-50"}`}
          >
            {t.label}
          </button>
        ))}
      </div>
      <p className="text-sm text-slate-500">{tab.help}</p>

      {admin && (
        <div className="bg-white rounded-xl border border-slate-200 p-5">
          <h3 className="font-semibold text-slate-800 mb-3">Add to {tab.label}</h3>
          <div className="flex gap-3">
            <input
              value={domain}
              maxLength={2048}
              onChange={(e) => {
                setDomain(e.target.value);
                setFieldError("");
              }}
              onKeyDown={(e) => e.key === "Enter" && domain.trim() && setConfirmAdd(true)}
              aria-label="Domain to add"
              aria-invalid={!!fieldError}
              placeholder="example.com"
              className={`flex-1 ${cls} ${fieldError ? "border-red-400" : ""}`}
            />
            <input value={note} maxLength={500} onChange={(e) => setNote(e.target.value)} aria-label="Note" placeholder="Note (optional)" className={`w-60 ${cls}`} />
            <button onClick={() => setConfirmAdd(true)} disabled={busy || !domain.trim()} className="bg-[#1e3a5f] text-white px-5 py-2.5 rounded-lg text-sm font-semibold hover:bg-[#162d4a] disabled:opacity-50">+ Add</button>
          </div>
          {fieldError && <p className="text-red-500 text-xs mt-1.5">{fieldError}</p>}
        </div>
      )}

      <div className="bg-white rounded-xl border border-slate-200 overflow-hidden">
        <div className="px-5 py-4 border-b border-slate-100 flex items-center justify-between gap-3">
          <h3 className="font-semibold text-slate-800">{tab.label} ({total})</h3>
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                setPage(1);
                setQ(search.trim());
              }
            }}
            aria-label="Search"
            placeholder="Search, press Enter"
            className={`w-56 ${cls} py-1.5`}
          />
        </div>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="text-xs text-slate-500 bg-slate-50 border-b border-slate-200">
                {["Domain", "Note", "Added", "By", ...(admin ? ["Action"] : [])].map((h) => <th key={h} className="text-left px-5 py-3 font-medium">{h}</th>)}
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {entries.map((e) => (
                <tr key={e.id} className="hover:bg-slate-50">
                  <td className="px-5 py-3 text-sm font-mono text-slate-700 break-all">{e.domain}</td>
                  <td className="px-5 py-3 text-sm text-slate-500">{e.note ?? ""}</td>
                  <td className="px-5 py-3 text-sm text-slate-600 whitespace-nowrap">{day(e.added_at)}</td>
                  <td className="px-5 py-3 text-sm text-slate-600">{e.added_by ?? "System"}</td>
                  {admin && (
                    <td className="px-5 py-3">
                      {e.active ? <button onClick={() => setTarget(e)} className="text-red-500 text-sm font-medium hover:underline">Switch off</button> : <Badge tone="slate">Off</Badge>}
                    </td>
                  )}
                </tr>
              ))}
              {entries.length === 0 && (
                <tr>
                  <td colSpan={admin ? 5 : 4} className="px-5 py-10 text-center text-slate-400 text-sm">{loading ? "Loading…" : "No entries."}</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
        <Pager page={page} perPage={PER_PAGE} total={total} onPage={setPage} />
      </div>

      {confirmAdd && (
        <ConfirmDialog
          title={`Add to ${tab.label}?`}
          tone={type === "blacklist" || type === "not_trusted" ? "red" : "green"}
          confirmLabel="Add"
          busy={busy}
          onConfirm={add}
          onCancel={() => setConfirmAdd(false)}
        >
          <p className="font-mono mb-1 break-all">{domain.trim()}</p>
          <p>This changes detection for every user straight away.</p>
        </ConfirmDialog>
      )}
      {target && (
        <ConfirmDialog title="Switch this entry off?" tone="red" confirmLabel="Switch off" busy={busy} onConfirm={remove} onCancel={() => setTarget(null)}>
          <p className="font-mono mb-1 break-all">{target.domain}</p>
          <p>It stays in the history but the detector stops using it.</p>
        </ConfirmDialog>
      )}
    </div>
  );
}
