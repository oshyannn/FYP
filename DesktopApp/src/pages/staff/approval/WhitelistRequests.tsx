import { useCallback, useEffect, useState } from "react";
import { api, problem } from "../../../api";
import Badge from "../../../components/Badge";
import ConfirmDialog from "../../../components/ConfirmDialog";
import EmployerReasonModal from "../../../components/EmployerReasonModal";
import Modal from "../../../components/Modal";
import Pager from "../../../components/Pager";
import StatusBadge from "../../../components/StatusBadge";
import { Alert } from "../../../components/ui";
import type { StaffRole } from "../../../lib/admin";
import { reviewLabel, reviewTone, REVIEW_PER_PAGE, scoreClass, shortDate } from "../../../lib/approvals";
import type { WhitelistRequest } from "../../../lib/approvals";
import { validateUrlInput } from "../../../lib/urlValidation";

interface Props {
  role: StaffRole;
  onSessionEnd: () => void;
  /** called after a decision so the tab badges can refresh */
  onChanged: () => void;
}

type Action = "approve" | "reject" | "delete";
const selectCls =
  "px-3 py-2 border border-slate-300 rounded-lg text-sm bg-white text-slate-700 focus:outline-none focus:border-[#1e3a5f]";

export default function WhitelistRequests({ role, onSessionEnd, onChanged }: Props) {
  const isEmployer = role === "employer";

  const [rows, setRows] = useState<WhitelistRequest[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState("");
  const [q, setQ] = useState("");
  const [status, setStatus] = useState("");

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [done, setDone] = useState("");

  const [selected, setSelected] = useState<WhitelistRequest | null>(null);
  const [confirm, setConfirm] = useState<{ item: WhitelistRequest; action: Action } | null>(null);
  const [editing, setEditing] = useState<WhitelistRequest | null>(null);
  const [editUrl, setEditUrl] = useState("");
  const [editReason, setEditReason] = useState("");
  const [editErr, setEditErr] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    const t = window.setTimeout(() => {
      setQ(search.trim());
      setPage(1);
    }, 300);
    return () => window.clearTimeout(t);
  }, [search]);

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    const qs = new URLSearchParams({ page: String(page), per_page: String(REVIEW_PER_PAGE) });
    if (status) qs.set("status", status);
    if (q) qs.set("search", q);
    const res = await api.get(`/api/staff/whitelist-requests?${qs.toString()}`);
    setLoading(false);
    if (res.status === 401) return onSessionEnd();
    if (res.status !== 200) return setError(problem(res).message);
    setRows(res.data.requests as WhitelistRequest[]);
    setTotal(res.data.total as number);
  }, [page, status, q, onSessionEnd]);

  useEffect(() => {
    load();
  }, [load]);

  async function decide(reasonText?: string) {
    if (!confirm || busy) return;
    setBusy(true);
    setError("");
    const { item, action } = confirm;
    const res =
      action === "delete"
        ? await api.del(`/api/staff/whitelist-requests/${item.id}`, reasonText ? { reason: reasonText } : undefined)
        : await api.post(`/api/staff/whitelist-requests/${item.id}/review`, {
            decision: action,
            ...(reasonText ? { note: reasonText } : {}),
          });
    setBusy(false);
    if (res.status === 401) return onSessionEnd();
    setConfirm(null);
    setSelected(null);
    if (res.status === 200) {
      setDone(
        action === "approve"
          ? `${item.domain} was approved and added to the Global Trusted List.`
          : action === "delete"
            ? `${item.domain} was removed from the Global Trusted List.`
            : `${item.domain} was rejected.`,
      );
      load();
      onChanged();
    } else {
      setError(problem(res).message);
    }
  }

  async function saveEdit() {
    if (!editing || busy) return;
    const parsed = validateUrlInput(editUrl);
    const e: Record<string, string> = {};
    if (!parsed.valid) e.url = parsed.error;
    if (isEmployer && editReason.trim().length < 3) e.reason = "Please enter a reason (at least 3 characters).";
    setEditErr(e);
    if (Object.keys(e).length) return;

    setBusy(true);
    setError("");
    const res = await api.patch(`/api/staff/whitelist-requests/${editing.id}`, {
      url: editUrl.trim(),
      ...(editReason.trim() ? { reason: editReason.trim() } : {}),
    });
    setBusy(false);
    if (res.status === 401) return onSessionEnd();
    if (res.status === 200) {
      setEditing(null);
      setDone("Approved whitelist entry updated globally.");
      load();
      onChanged();
      return;
    }
    const p = problem(res);
    if (Object.keys(p.fields).length) setEditErr(p.fields);
    else setEditErr({ url: p.message });
  }

  const parsedEdit = validateUrlInput(editUrl);

  return (
    <div className="space-y-4">
      {error && <Alert kind="error">{error}</Alert>}
      {done && <Alert kind="success">{done}</Alert>}

      <div className="bg-white rounded-xl border border-slate-200 p-4 flex flex-wrap gap-3 items-center">
        <input
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          maxLength={100}
          aria-label="Search whitelist requests"
          placeholder="Search domain or requester email..."
          className="flex-1 min-w-48 px-3.5 py-2 border border-slate-300 rounded-lg text-sm placeholder-slate-400 focus:outline-none focus:border-[#1e3a5f] focus:ring-2 focus:ring-[#1e3a5f]/10"
        />
        <select
          value={status}
          onChange={(e) => {
            setStatus(e.target.value);
            setPage(1);
          }}
          aria-label="Filter by status"
          className={selectCls}
        >
          <option value="">All Status</option>
          <option value="pending">Pending</option>
          <option value="approved">Approved</option>
          <option value="rejected">Rejected</option>
        </select>
        <button
          type="button"
          onClick={() => {
            setSearch("");
            setQ("");
            setStatus("");
            setPage(1);
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
                {["URL", "Submitted By", "Date", "Detector Score", "Status", "Actions"].map((h) => (
                  <th key={h} className="text-left px-5 py-3 font-medium whitespace-nowrap">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {rows.map((row) => (
                <tr key={row.id} className="hover:bg-slate-50 transition-colors">
                  <td className="px-5 py-3.5 text-sm font-mono text-slate-700">
                    {row.domain}
                    {row.path && <span className="ml-2 text-xs font-sans text-slate-400">specific page</span>}
                  </td>
                  <td className="px-5 py-3.5 text-sm text-slate-600">{row.requester_email}</td>
                  <td className="px-5 py-3.5 text-sm text-slate-500 whitespace-nowrap">{shortDate(row.created_at)}</td>
                  <td className="px-5 py-3.5 text-sm font-semibold">
                    {row.risk_score === null ? (
                      <span className="text-slate-400" title="The detector had no data about this website">
                        —
                      </span>
                    ) : (
                      <span className={scoreClass(row.risk_score)}>{Math.round(row.risk_score)}/100</span>
                    )}
                  </td>
                  <td className="px-5 py-3.5">
                    <Badge tone={reviewTone(row.status)}>{reviewLabel(row.status)}</Badge>
                  </td>
                  <td className="px-5 py-3.5">
                    <div className="flex items-center gap-3 whitespace-nowrap">
                      <button
                        type="button"
                        onClick={() => {
                          setDone("");
                          setSelected(row);
                        }}
                        className="text-[#1e3a5f] text-sm font-medium hover:underline"
                      >
                        Review
                      </button>
                      {row.status === "approved" && (
                        <>
                          <button
                            type="button"
                            onClick={() => {
                              setDone("");
                              setEditUrl(row.domain);
                              setEditReason("");
                              setEditErr({});
                              setEditing(row);
                            }}
                            className="text-slate-600 text-sm font-medium hover:underline"
                          >
                            Modify
                          </button>
                          <button
                            type="button"
                            onClick={() => {
                              setDone("");
                              setConfirm({ item: row, action: "delete" });
                            }}
                            className="text-red-500 text-sm font-medium hover:underline"
                          >
                            Delete
                          </button>
                        </>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
              {rows.length === 0 && (
                <tr>
                  <td colSpan={6} className="px-5 py-10 text-center text-slate-400 text-sm">
                    {loading ? "Loading…" : "No whitelist requests found."}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
        <Pager page={page} perPage={REVIEW_PER_PAGE} total={total} onPage={setPage} />
      </div>

      {selected && (
        <Modal
          title="Whitelist Request Review"
          subtitle="Approved entries apply globally to all users"
          onClose={() => setSelected(null)}
          footer={
            selected.status === "pending" ? (
              <>
                <button type="button" onClick={() => setSelected(null)} className="flex-1 border border-slate-300 text-slate-700 py-2.5 rounded-lg text-sm font-medium hover:bg-slate-50">
                  Cancel
                </button>
                <button type="button" onClick={() => setConfirm({ item: selected, action: "reject" })} className="flex-1 border border-red-300 text-red-600 py-2.5 rounded-lg text-sm font-medium hover:bg-red-50">
                  Reject
                </button>
                <button type="button" onClick={() => setConfirm({ item: selected, action: "approve" })} className="flex-1 bg-green-600 text-white py-2.5 rounded-lg text-sm font-semibold hover:bg-green-700">
                  Approve Globally
                </button>
              </>
            ) : (
              <button type="button" onClick={() => setSelected(null)} className="w-full border border-slate-300 text-slate-700 py-2.5 rounded-lg text-sm font-medium hover:bg-slate-50">
                Close
              </button>
            )
          }
        >
          <div className="divide-y divide-slate-100 text-sm">
            {(
              [
                ["URL", <span className="font-mono text-slate-800 break-all">{selected.domain}</span>],
                ["Submitted By", <span className="text-slate-800">{selected.requester_email}</span>],
                ["Requested", <span className="text-slate-800">{shortDate(selected.created_at)}</span>],
                [
                  "Detector Score",
                  selected.risk_score === null ? (
                    <span className="text-slate-500">Not available</span>
                  ) : (
                    <span className={`font-bold ${scoreClass(selected.risk_score)}`}>{Math.round(selected.risk_score)}/100</span>
                  ),
                ],
                ["Detector Verdict", <StatusBadge level={selected.risk_level} />],
                ["Reason", <span className="text-slate-800">{selected.reason || "Not provided"}</span>],
              ] as [string, React.ReactNode][]
            ).map(([l, v]) => (
              <div key={l} className="flex items-center justify-between py-2.5 gap-4">
                <span className="text-slate-500 shrink-0">{l}</span>
                <div className="text-right min-w-0">{v}</div>
              </div>
            ))}
          </div>

          {selected.status === "pending" && selected.risk_level === "malicious" && (
            <p className="mt-4 text-xs text-red-700 bg-red-50 border border-red-200 rounded-lg p-3">
              The detector flagged this website as malicious. Even if whitelisted, malicious verdicts are never overridden.
            </p>
          )}
          {selected.status !== "pending" && (
            <p className="mt-4 text-xs text-slate-500">
              {reviewLabel(selected.status)}
              {selected.reviewed_by_name ? ` by ${selected.reviewed_by_name}` : ""}
              {selected.reviewed_at ? ` on ${shortDate(selected.reviewed_at)}` : ""}.
            </p>
          )}
        </Modal>
      )}

      {editing && (
        <Modal
          title="Modify Approved Whitelist Entry"
          subtitle="Changes apply globally to all users"
          onClose={() => setEditing(null)}
          footer={
            <>
              <button type="button" onClick={() => setEditing(null)} className="flex-1 border border-slate-300 text-slate-700 py-2.5 rounded-lg text-sm font-medium hover:bg-slate-50">
                Cancel
              </button>
              <button type="button" onClick={saveEdit} disabled={busy} className="flex-1 bg-[#1e3a5f] text-white py-2.5 rounded-lg text-sm font-semibold hover:bg-[#162d4a] disabled:opacity-60">
                {busy ? "Saving…" : "Save Changes"}
              </button>
            </>
          }
        >
          <div className="space-y-4">
            <div>
              <div className="flex items-center justify-between mb-1.5">
                <label htmlFor="wl-edit-url" className="block text-sm font-medium text-slate-700">
                  Domain or Page URL <span className="text-red-500">*</span>
                </label>
                {editUrl.trim() && parsedEdit.valid && (
                  <span className={`text-[11px] font-medium px-2 py-0.5 rounded-full ${parsedEdit.scope === "domain" ? "bg-purple-50 text-purple-700" : "bg-blue-50 text-blue-700"}`}>
                    {parsedEdit.scope === "domain" ? "Covers full domain" : "Specific page URL"}
                  </span>
                )}
              </div>
              <input
                id="wl-edit-url"
                value={editUrl}
                maxLength={2048}
                onChange={(e) => {
                  setEditUrl(e.target.value);
                  setEditErr((prev) => ({ ...prev, url: "" }));
                }}
                className="w-full px-3.5 py-2.5 border border-slate-300 rounded-lg text-sm font-mono focus:outline-none focus:border-[#1e3a5f]"
              />
              {editErr.url && <p className="text-red-500 text-xs mt-1">{editErr.url}</p>}
            </div>
            {isEmployer && (
              <div>
                <label htmlFor="wl-edit-reason" className="block text-sm font-medium text-slate-700 mb-1.5">
                  Reason <span className="text-red-500">*</span>
                </label>
                <textarea
                  id="wl-edit-reason"
                  value={editReason}
                  maxLength={500}
                  rows={2}
                  onChange={(e) => {
                    setEditReason(e.target.value);
                    setEditErr((prev) => ({ ...prev, reason: "" }));
                  }}
                  placeholder="Why are you modifying this whitelist entry?"
                  className="w-full px-3.5 py-2 border border-slate-300 rounded-lg text-sm resize-none focus:outline-none focus:border-[#1e3a5f]"
                />
                {editErr.reason && <p className="text-red-500 text-xs mt-1">{editErr.reason}</p>}
              </div>
            )}
          </div>
        </Modal>
      )}

      {confirm && isEmployer ? (
        <EmployerReasonModal
          title={
            confirm.action === "approve"
              ? "Approve Globally"
              : confirm.action === "delete"
                ? "Delete Whitelist Entry"
                : "Reject Whitelist Request"
          }
          subtitle={confirm.item.domain}
          description={
            confirm.action === "approve"
              ? "This website will be trusted globally for all users."
              : confirm.action === "delete"
                ? "This website will be removed from the global trusted list."
                : "This whitelist request will be rejected."
          }
          tone={confirm.action === "approve" ? "green" : "red"}
          confirmLabel={confirm.action === "approve" ? "Approve Globally" : confirm.action === "delete" ? "Delete" : "Reject"}
          busy={busy}
          onConfirm={(r) => decide(r)}
          onCancel={() => setConfirm(null)}
        />
      ) : confirm ? (
        <ConfirmDialog
          title={
            confirm.action === "approve"
              ? "Approve Globally?"
              : confirm.action === "delete"
                ? "Delete Approved Entry?"
                : "Confirm Rejection"
          }
          tone={confirm.action === "approve" ? "green" : "red"}
          confirmLabel={confirm.action === "approve" ? "Approve" : confirm.action === "delete" ? "Delete" : "Reject"}
          busy={busy}
          onConfirm={() => decide()}
          onCancel={() => setConfirm(null)}
        >
          <p className="font-mono mb-1 break-all">{confirm.item.domain}</p>
          <p>
            {confirm.action === "approve"
              ? "This website will be added to the Global Trusted List and trusted for every user."
              : confirm.action === "delete"
                ? "This website will be removed from the Global Trusted List."
                : "Are you sure you want to reject this whitelist request?"}
          </p>
        </ConfirmDialog>
      ) : null}
    </div>
  );
}
