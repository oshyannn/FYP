import { useCallback, useEffect, useState } from "react";
import { api, problem } from "../../api";
import Badge from "../../components/Badge";
import ConfirmDialog from "../../components/ConfirmDialog";
import Pager from "../../components/Pager";
import { Alert } from "../../components/ui";
import { reviewLabel, reviewTone, shortDate, WHITELIST_PER_PAGE } from "../../lib/approvals";
import type { WhitelistEntry, WhitelistRequest } from "../../lib/approvals";

interface Props {
  /** user: own trusted websites (a new one is a request that an employer or admin approves) | admin: the list for everyone */
  role: "user" | "admin";
  onSessionEnd: () => void;
}

const inputCls =
  "w-full px-3.5 py-2.5 border rounded-lg text-sm placeholder-slate-400 focus:outline-none focus:ring-2 transition-colors";

export default function Whitelist({ role, onSessionEnd }: Props) {
  const admin = role === "admin";
  const [entries, setEntries] = useState<WhitelistEntry[]>([]);
  const [requests, setRequests] = useState<WhitelistRequest[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [input, setInput] = useState("");
  const [reason, setReason] = useState("");
  const [fieldError, setFieldError] = useState("");
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
  }, [page]);

  useEffect(() => {
    load();
  }, [load]);

  async function add() {
    const value = input.trim();
    if (!value || adding) return;
    setAdding(true);
    setError("");
    setFieldError("");
    setNotice("");
    const res = await api.post("/api/whitelist", admin ? { url: value } : { url: value, reason: reason.trim() || undefined });
    setAdding(false);
    if (res.status === 401) return onSessionEnd();
    if (res.status === 201) {
      setInput("");
      setReason("");
      setNotice(
        admin
          ? `${res.data.entry.domain} is now trusted for every user.`
          : `Request sent for ${res.data.request.domain}. It will appear in your trusted list once an employer or administrator approves it.`,
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
        <h2 className="text-xl font-bold text-slate-900">Trusted Websites</h2>
        <p className="text-slate-500 text-sm mt-0.5">
          {admin
            ? "Websites added here are treated as trusted by SafeBrowse for every user."
            : "Websites added to the whitelist will be treated as trusted by SafeBrowse."}
        </p>
      </div>

      {error && <Alert kind="error">{error}</Alert>}
      {notice && <Alert kind="success">{notice}</Alert>}

      <div className="bg-white rounded-xl border border-slate-200 p-5">
        <h3 className="font-semibold text-slate-800 mb-3">Add Trusted Website</h3>
        <div className="flex gap-3">
          <input
            value={input}
            maxLength={2048}
            onChange={(e) => {
              setInput(e.target.value);
              setFieldError("");
            }}
            onKeyDown={(e) => e.key === "Enter" && add()}
            aria-label="Website to trust"
            aria-invalid={!!fieldError}
            placeholder="Enter URL or domain, e.g. example.com"
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
              placeholder="Why should this website be trusted? (optional)"
              className={`mt-3 ${inputCls} border-slate-300 focus:border-[#1e3a5f] focus:ring-[#1e3a5f]/10`}
            />
            <p className="text-slate-400 text-xs mt-2">
              An employer or administrator reviews each request. Once approved, the website is shown as safe in your scans, unless it is
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
          <h3 className="font-semibold text-slate-800">Trusted Domains ({total})</h3>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="text-xs text-slate-500 bg-slate-50 border-b border-slate-200">
                {["Domain", "Added Date", "Added By", "Action"].map((h) => (
                  <th key={h} className="text-left px-5 py-3 font-medium">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {entries.map((row) => (
                <tr key={row.id} className="hover:bg-slate-50 transition-colors">
                  <td className="px-5 py-3.5 text-sm font-mono text-slate-700">{row.domain}</td>
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
                    {loading ? "Loading…" : "No trusted websites added."}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
        <Pager page={page} perPage={WHITELIST_PER_PAGE} total={total} onPage={setPage} />
      </div>

      {target && (
        <ConfirmDialog title="Remove Trusted Website?" tone="red" confirmLabel="Remove" busy={removing} onConfirm={remove} onCancel={() => setTarget(null)}>
          <p className="font-mono mb-1 break-all">{target.domain}</p>
          <p>This domain will no longer be trusted by SafeBrowse.</p>
        </ConfirmDialog>
      )}
    </div>
  );
}
