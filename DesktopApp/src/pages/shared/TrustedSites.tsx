import { useCallback, useEffect, useState } from "react";
import { api, problem } from "../../api";
import Badge from "../../components/Badge";
import ConfirmDialog from "../../components/ConfirmDialog";
import Pager from "../../components/Pager";
import { Alert } from "../../components/ui";
import { reviewLabel, reviewTone, shortDate, WHITELIST_PER_PAGE } from "../../lib/approvals";
import type { WhitelistEntry, WhitelistRequest } from "../../lib/approvals";
import { normalizeUrlKey, validateUrlInput } from "../../lib/urlValidation";

interface Props {
  /** user: own trusted sites (a new one is a request that an employer or admin approves) | admin: the list for everyone */
  role: "user" | "admin";
  onSessionEnd: () => void;
}

const inputCls =
  "w-full px-3.5 py-2.5 border rounded-lg text-sm placeholder-slate-400 focus:outline-none focus:ring-2 transition-colors";

export default function TrustedSites({ role, onSessionEnd }: Props) {
  const admin = role === "admin";
  const [entries, setEntries] = useState<WhitelistEntry[]>([]);
  const [requests, setRequests] = useState<WhitelistRequest[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [input, setInput] = useState("");
  const [reason, setReason] = useState("");
  const [fieldError, setFieldError] = useState("");
  const [warnings, setWarnings] = useState<string[]>([]);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [loading, setLoading] = useState(true);
  const [adding, setAdding] = useState(false);
  const [target, setTarget] = useState<WhitelistEntry | null>(null);
  const [removing, setRemoving] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    const res = await api.get(`/api/whitelist?page=${page}&per_page=${WHITELIST_PER_PAGE}`);
    setLoading(false);
    if (res.status === 401) return onSessionEnd();
    if (res.status !== 200) return setError(problem(res).message);
    setEntries(res.data.entries as WhitelistEntry[]);
    setRequests(res.data.requests as WhitelistRequest[]);
    setTotal(res.data.total as number);
  }, [page, onSessionEnd]);

  useEffect(() => {
    load();
  }, [load]);

  async function add() {
    const value = input.trim();
    if (!value || adding) return;
    const parsed = validateUrlInput(value);
    if (!parsed.valid) {
      setFieldError(parsed.error);
      return;
    }
    const key = normalizeUrlKey(value);
    if (entries.some((e) => normalizeUrlKey(e.domain) === key) || requests.some((r) => r.status === "pending" && normalizeUrlKey(r.domain) === key)) {
      setFieldError("This URL or domain is already listed or pending review.");
      return;
    }
    setAdding(true);
    setError("");
    setFieldError("");
    setNotice("");
    setWarnings([]);
    const res = await api.post("/api/whitelist", admin ? { url: value } : { url: value, reason: reason.trim() || undefined });
    setAdding(false);
    if (res.status === 401) return onSessionEnd();
    if (res.status === 201) {
      const shown = res.data.request?.domain ?? res.data.entry?.domain ?? value;
      setInput("");
      setReason("");
      setWarnings((res.data.warnings as string[]) ?? []);
      setNotice(
        admin
          ? `${shown} is now trusted for every user.`
          : `Request sent for ${shown}. It will appear in your trusted sites once an employer or administrator approves it.`,
      );
      if (page !== 1) setPage(1);
      else load();
      return;
    }
    if (res.status === 429) return setError("Too many requests. Wait a moment and try again.");
    const p = problem(res);
    if (res.status === 400 || res.status === 409) setFieldError(p.message);
    else setError(p.message);
  }

  async function remove() {
    if (!target || removing) return;
    setRemoving(true);
    const res = await api.del(`/api/whitelist/${target.id}`);
    setRemoving(false);
    if (res.status === 401) return onSessionEnd();
    setTarget(null);
    if (res.status !== 200 && res.status !== 404) return setError(problem(res).message);
    if (page > 1 && entries.length <= 1) setPage(page - 1);
    else load();
  }

  return (
    <div className="max-w-3xl space-y-5">
      <div>
        <h2 className="text-xl font-bold text-slate-900">Trusted Sites</h2>
        <p className="text-slate-500 text-sm mt-0.5">
          {admin
            ? "Websites or pages added here are treated as trusted by SafeBrowse for every user."
            : "Websites or pages you add are treated as trusted by SafeBrowse once approved."}
        </p>
      </div>

      {error && <Alert kind="error">{error}</Alert>}
      {notice && <Alert kind="success">{notice}</Alert>}
      {warnings.length > 0 && (
        <div className="rounded-lg border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-800 space-y-1">
          {warnings.map((w) => (
            <p key={w}>{w}</p>
          ))}
        </div>
      )}

      <div className="bg-white rounded-xl border border-slate-200 p-5">
        <div className="flex items-center justify-between mb-3">
          <h3 className="font-semibold text-slate-800">Add Trusted Site</h3>
          {input.trim() && validateUrlInput(input).valid && (
            <span className={`text-[11px] font-medium px-2 py-0.5 rounded-full ${validateUrlInput(input).scope === "domain" ? "bg-purple-50 text-purple-700" : "bg-blue-50 text-blue-700"}`}>
              {validateUrlInput(input).scope === "domain" ? "Covers full domain" : "Specific page URL"}
            </span>
          )}
        </div>
        <div className="flex gap-3">
          <input
            value={input}
            maxLength={2048}
            onChange={(e) => {
              setInput(e.target.value);
              setFieldError("");
              setWarnings([]);
            }}
            onKeyDown={(e) => e.key === "Enter" && add()}
            aria-label="Website or page to trust"
            aria-invalid={!!fieldError}
            placeholder="example.com, or one page such as example.com/shop"
            className={`flex-1 ${inputCls} ${fieldError ? "border-red-400 focus:border-red-400 focus:ring-red-100" : "border-slate-300 focus:border-[#1e3a5f] focus:ring-[#1e3a5f]/10"}`}
          />
          <button
            onClick={add}
            disabled={adding || !input.trim()}
            className="bg-[#1e3a5f] text-white px-5 py-2.5 rounded-lg text-sm font-semibold hover:bg-[#162d4a] disabled:opacity-50 transition-colors"
          >
            {adding ? "Adding…" : "+ Add"}
          </button>
        </div>
        {fieldError && <p className="text-red-500 text-xs mt-1.5">{fieldError}</p>}
        {!admin && (
          <>
            <input
              value={reason}
              maxLength={500}
              onChange={(e) => setReason(e.target.value)}
              aria-label="Reason (optional)"
              placeholder="Why should this site be trusted? (optional)"
              className={`mt-3 ${inputCls} border-slate-300 focus:border-[#1e3a5f] focus:ring-[#1e3a5f]/10`}
            />
            <p className="text-slate-400 text-xs mt-2">
              An employer or administrator reviews each request. Once approved, the site is shown as safe in your scans, unless it is
              detected as malicious.
            </p>
          </>
        )}
      </div>

      {!admin && requests.length > 0 && (
        <div className="bg-white rounded-xl border border-slate-200 overflow-hidden">
          <div className="px-5 py-4 border-b border-slate-100">
            <h3 className="font-semibold text-slate-800">Your Requests</h3>
          </div>
          <ul className="divide-y divide-slate-100">
            {requests.map((r) => (
              <li key={r.id} className="px-5 py-3.5 flex items-start justify-between gap-4">
                <div className="min-w-0">
                  <p className="text-sm font-mono text-slate-700 break-all">{r.domain}</p>
                  <p className="text-xs text-slate-400 mt-0.5">Requested {shortDate(r.created_at)}</p>
                  {r.status === "rejected" && r.review_note && <p className="text-xs text-slate-500 mt-1">Reviewer note: {r.review_note}</p>}
                </div>
                <Badge tone={reviewTone(r.status)}>{reviewLabel(r.status)}</Badge>
              </li>
            ))}
          </ul>
        </div>
      )}

      <div className="bg-white rounded-xl border border-slate-200 overflow-hidden">
        <div className="px-5 py-4 border-b border-slate-100">
          <h3 className="font-semibold text-slate-800">Trusted Addresses ({total})</h3>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="text-xs text-slate-500 bg-slate-50 border-b border-slate-200">
                {["Address", "Added Date", "Added By", "Action"].map((h) => (
                  <th key={h} className="text-left px-5 py-3 font-medium">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {entries.map((row) => (
                <tr key={row.id} className="hover:bg-slate-50 transition-colors">
                  <td className="px-5 py-3.5 text-sm font-mono text-slate-700 break-all">
                    {row.domain}
                    {row.path && <span className="ml-2 text-xs font-sans text-slate-400">one page</span>}
                  </td>
                  <td className="px-5 py-3.5 text-sm text-slate-600 whitespace-nowrap">{shortDate(row.added_at)}</td>
                  <td className="px-5 py-3.5 text-sm text-slate-600">{row.added_by}</td>
                  <td className="px-5 py-3.5">
                    <button onClick={() => setTarget(row)} className="text-red-500 text-sm font-medium hover:underline">
                      Remove
                    </button>
                  </td>
                </tr>
              ))}
              {entries.length === 0 && (
                <tr>
                  <td colSpan={4} className="px-5 py-10 text-center text-slate-400 text-sm">
                    {loading ? "Loading…" : "No trusted sites added."}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
        <Pager page={page} perPage={WHITELIST_PER_PAGE} total={total} onPage={setPage} />
      </div>

      {target && (
        <ConfirmDialog title="Remove Trusted Site?" tone="red" confirmLabel="Remove" busy={removing} onConfirm={remove} onCancel={() => setTarget(null)}>
          <p className="font-mono mb-1 break-all">{target.domain}</p>
          <p>This address will no longer be trusted by SafeBrowse.</p>
        </ConfirmDialog>
      )}
    </div>
  );
}
