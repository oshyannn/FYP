import { useCallback, useEffect, useState } from "react";
import { api, problem } from "../../../api";
import Badge from "../../../components/Badge";
import ConfirmDialog from "../../../components/ConfirmDialog";
import EmployerReasonModal from "../../../components/EmployerReasonModal";
import Modal from "../../../components/Modal";
import Pager from "../../../components/Pager";
import ScopeChoice from "../../../components/ScopeChoice";
import StatusBadge from "../../../components/StatusBadge";
import { Alert } from "../../../components/ui";
import type { StaffRole } from "../../../lib/admin";
import {
  isFrontPage,
  THREAT_TYPE_OPTIONS,
  threatStatusLabel,
  threatStatusTone,
  threatTypeLabel,
  threatTypeTone,
} from "../../../lib/threats";
import type { MatchScope, ThreatItem, ThreatStats } from "../../../lib/threats";
import ThreatFormModal from "./ThreatFormModal";

interface Props {
  role: StaffRole;
  reloadKey: number;
  onSessionEnd: () => void;
  onChanged: () => void;
}

const PER_PAGE = 10;
const selectCls =
  "px-3 py-2 border border-slate-300 rounded-lg text-sm bg-white text-slate-700 focus:outline-none focus:border-[#1e3a5f]";

export default function ThreatDetectionQueue({ role, reloadKey, onSessionEnd, onChanged }: Props) {
  const isEmployer = role === "employer";

  const [rows, setRows] = useState<ThreatItem[]>([]);
  const [stats, setStats] = useState<ThreatStats | null>(null);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);

  const [search, setSearch] = useState("");
  const [q, setQ] = useState("");
  const [status, setStatus] = useState("pending_review");
  const [type, setType] = useState("");
  const [severity, setSeverity] = useState("");
  const [sort, setSort] = useState("newest");

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [done, setDone] = useState("");

  const [selected, setSelected] = useState<ThreatItem | null>(null);
  const [editing, setEditing] = useState<ThreatItem | null>(null);
  const [scope, setScope] = useState<MatchScope>("auto");
  const [confirmAction, setConfirmAction] = useState<{ item: ThreatItem; kind: "approve" | "remove" | "delete" } | null>(null);
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
    const qs = new URLSearchParams({
      page: String(page),
      per_page: String(PER_PAGE),
      sort,
    });
    if (status) qs.set("status", status);
    if (q) qs.set("search", q);
    if (type) qs.set("type", type);
    if (severity) qs.set("risk_level", severity);

    const res = await api.get(`/api/threats?${qs.toString()}`);
    setLoading(false);
    if (res.status === 401) return onSessionEnd();
    if (res.status !== 200) return setError(problem(res).message);
    setRows(res.data.threats as ThreatItem[]);
    setTotal(res.data.total as number);
    setStats(res.data.stats as ThreatStats);
  }, [page, status, q, type, severity, sort, reloadKey, onSessionEnd]);

  useEffect(() => {
    load();
  }, [load]);

  async function executeAction(reasonText?: string) {
    if (!confirmAction || busy) return;
    setBusy(true);
    setError("");
    const { item, kind } = confirmAction;
    let res;
    if (kind === "delete") {
      res = await api.del(`/api/staff/threats/${item.id}`, reasonText ? { reason: reasonText } : undefined);
    } else {
      res = await api.post(`/api/staff/threats/${item.id}/review`, {
        decision: kind,
        ...(kind === "approve" && isFrontPage(item.url) && scope !== "auto" ? { match_scope: scope } : {}),
        ...(reasonText ? { reason: reasonText } : {}),
      });
    }
    setBusy(false);
    if (res.status === 401) return onSessionEnd();
    setConfirmAction(null);
    setSelected(null);
    if (res.status !== 200) {
      setError(problem(res).message);
      return;
    }
    setDone(
      kind === "approve"
        ? `${item.url} approved and added to the Detection List.`
        : kind === "delete"
          ? `${item.url} deleted.`
          : `${item.url} rejected.`,
    );
    load();
    onChanged();
  }

  function clearFilters() {
    setSearch("");
    setQ("");
    setStatus("pending_review");
    setType("");
    setSeverity("");
    setSort("newest");
    setPage(1);
  }

  const cards = [
    { label: "Pending Review", value: stats?.pending ?? 0, color: "text-amber-600", bg: "bg-amber-50", filter: "pending_review" },
    { label: "Approved (Active)", value: stats?.total ?? 0, color: "text-green-600", bg: "bg-green-50", filter: "active" },
    { label: "Rejected / Removed", value: stats?.revoked ?? 0, color: "text-slate-600", bg: "bg-slate-50", filter: "revoked" },
  ];

  return (
    <div className="space-y-4">
      {error && <Alert kind="error">{error}</Alert>}
      {done && <Alert kind="success">{done}</Alert>}

      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        {cards.map((c) => (
          <button
            key={c.label}
            type="button"
            onClick={() => {
              setStatus(c.filter);
              setPage(1);
            }}
            className={`${c.bg} rounded-xl border p-4 text-center transition-all ${
              status === c.filter ? "border-[#1e3a5f] ring-2 ring-[#1e3a5f]/15" : "border-slate-200 hover:border-slate-300"
            }`}
          >
            <div className={`text-2xl font-bold ${c.color}`}>{c.value.toLocaleString()}</div>
            <div className="text-slate-600 text-xs font-medium mt-1">{c.label}</div>
          </button>
        ))}
      </div>

      <div className="bg-white rounded-xl border border-slate-200 p-4 flex flex-wrap gap-3 items-center">
        <input
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          maxLength={200}
          aria-label="Search detected URL"
          placeholder="Search URL or domain..."
          className="flex-1 min-w-48 px-3.5 py-2 border border-slate-300 rounded-lg text-sm placeholder-slate-400 focus:outline-none focus:border-[#1e3a5f] focus:ring-2 focus:ring-[#1e3a5f]/10"
        />
        <select value={status} onChange={(e) => { setStatus(e.target.value); setPage(1); }} aria-label="Filter by status" className={selectCls}>
          <option value="">All Status</option>
          <option value="pending_review">Pending Review</option>
          <option value="active">Approved (Active)</option>
          <option value="revoked">Rejected / Removed</option>
        </select>
        <select value={type} onChange={(e) => { setType(e.target.value); setPage(1); }} aria-label="Filter by category" className={selectCls}>
          <option value="">All Categories</option>
          {THREAT_TYPE_OPTIONS.map(([v, l]) => (
            <option key={v} value={v}>{l}</option>
          ))}
        </select>
        <select value={severity} onChange={(e) => { setSeverity(e.target.value); setPage(1); }} aria-label="Filter by severity" className={selectCls}>
          <option value="">All Severities</option>
          <option value="malicious">Malicious</option>
          <option value="suspicious">Suspicious</option>
        </select>
        <select value={sort} onChange={(e) => { setSort(e.target.value); setPage(1); }} aria-label="Sort order" className={selectCls}>
          <option value="newest">Newest First</option>
          <option value="oldest">Oldest First</option>
          <option value="detections">Most Detected</option>
          <option value="url">URL (A–Z)</option>
        </select>
        <button type="button" onClick={clearFilters} className="px-3.5 py-2 border border-slate-300 rounded-lg text-sm text-slate-600 hover:bg-slate-50">
          Reset
        </button>
      </div>

      <div className="bg-white rounded-xl border border-slate-200 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="text-xs text-slate-500 bg-slate-50 border-b border-slate-200">
                {["URL", "Category", "Severity", "Detections", "Last Detected", "Status", "Actions"].map((h) => (
                  <th key={h} className="text-left px-5 py-3 font-medium whitespace-nowrap">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {rows.map((r) => (
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
                  <td className="px-5 py-3.5">
                    <Badge tone={threatStatusTone(r.status)}>{threatStatusLabel(r.status)}</Badge>
                  </td>
                  <td className="px-5 py-3.5">
                    <div className="flex items-center gap-3 whitespace-nowrap">
                      <button
                        type="button"
                        onClick={() => {
                          setDone("");
                          setScope(r.match_scope ?? "auto");
                          setSelected(r);
                        }}
                        className="text-[#1e3a5f] text-sm font-medium hover:underline"
                      >
                        Review
                      </button>
                      {r.status === "pending_review" && (
                        <>
                          <button
                            type="button"
                            onClick={() => {
                              setDone("");
                              setScope(r.match_scope ?? "auto");
                              setConfirmAction({ item: r, kind: "approve" });
                            }}
                            className="text-green-700 text-sm font-medium hover:underline"
                          >
                            Approve
                          </button>
                          <button
                            type="button"
                            onClick={() => {
                              setDone("");
                              setConfirmAction({ item: r, kind: "remove" });
                            }}
                            className="text-red-500 text-sm font-medium hover:underline"
                          >
                            Reject
                          </button>
                        </>
                      )}
                      {r.status === "active" && (
                        <>
                          <button
                            type="button"
                            onClick={() => {
                              setDone("");
                              setEditing(r);
                            }}
                            className="text-slate-600 text-sm font-medium hover:underline"
                          >
                            Modify
                          </button>
                          <button
                            type="button"
                            onClick={() => {
                              setDone("");
                              setConfirmAction({ item: r, kind: "delete" });
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
                  <td colSpan={7} className="px-5 py-10 text-center text-slate-400 text-sm">
                    {loading ? "Loading…" : "No matching threat detection records."}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
        <Pager page={page} perPage={PER_PAGE} total={total} onPage={setPage} />
      </div>

      {selected && (
        <Modal
          title="AI Threat Detection Details"
          subtitle="Review before publishing to the global Detection List"
          onClose={() => setSelected(null)}
          footer={
            <>
              <button type="button" onClick={() => setSelected(null)} className="flex-1 border border-slate-300 text-slate-700 py-2.5 rounded-lg text-sm font-medium hover:bg-slate-50">
                Close
              </button>
              {selected.status === "pending_review" && (
                <>
                  <button
                    type="button"
                    onClick={() => setConfirmAction({ item: selected, kind: "remove" })}
                    className="flex-1 border border-red-300 text-red-600 py-2.5 rounded-lg text-sm font-semibold hover:bg-red-50"
                  >
                    Reject
                  </button>
                  <button
                    type="button"
                    onClick={() => setConfirmAction({ item: selected, kind: "approve" })}
                    className="flex-1 bg-green-600 text-white py-2.5 rounded-lg text-sm font-semibold hover:bg-green-700"
                  >
                    Approve &amp; Add
                  </button>
                </>
              )}
              {selected.status === "active" && (
                <>
                  <button
                    type="button"
                    onClick={() => {
                      const item = selected;
                      setSelected(null);
                      setEditing(item);
                    }}
                    className="flex-1 border border-slate-300 text-slate-700 py-2.5 rounded-lg text-sm font-semibold hover:bg-slate-50"
                  >
                    Modify
                  </button>
                  <button
                    type="button"
                    onClick={() => setConfirmAction({ item: selected, kind: "delete" })}
                    className="flex-1 bg-red-600 text-white py-2.5 rounded-lg text-sm font-semibold hover:bg-red-700"
                  >
                    Delete
                  </button>
                </>
              )}
            </>
          }
        >
          <div className="divide-y divide-slate-100 text-sm">
            {(
              [
                ["URL", <span className="font-mono text-xs text-slate-800 break-all">{selected.url}</span>],
                ["Category", <Badge tone={threatTypeTone(selected.threat_type)}>{threatTypeLabel(selected.threat_type)}</Badge>],
                ["Severity", <StatusBadge level={selected.risk_level} />],
                ["Status", <Badge tone={threatStatusTone(selected.status)}>{threatStatusLabel(selected.status)}</Badge>],
                ["Detections", <span className="text-slate-700">{selected.detection_count}</span>],
                ...(isFrontPage(selected.url) ? [["Scope", <span className="text-slate-700">{selected.match_scope === "exact" ? "Exact page only" : "Whole domain"}</span>] as [string, React.ReactNode]] : []),
                ["First Detected", <span className="text-slate-700">{new Date(selected.created_at).toLocaleString()}</span>],
                ["Last Detected", <span className="text-slate-700">{new Date(selected.last_verified_at).toLocaleString()}</span>],
                ...(selected.notes ? [["Notes", <span className="text-slate-700 whitespace-pre-wrap">{selected.notes}</span>] as [string, React.ReactNode]] : []),
              ] as [string, React.ReactNode][]
            ).map(([l, v]) => (
              <div key={l} className="flex items-center justify-between py-2.5 gap-4">
                <span className="text-slate-500 shrink-0">{l}</span>
                <div className="text-right min-w-0">{v}</div>
              </div>
            ))}
          </div>
        </Modal>
      )}

      {editing && (
        <ThreatFormModal
          role={role}
          existing={editing}
          onClose={() => setEditing(null)}
          onSessionEnd={onSessionEnd}
          onSaved={(msg) => {
            setEditing(null);
            setDone(msg);
            load();
            onChanged();
          }}
        />
      )}

      {confirmAction && isEmployer ? (
        <EmployerReasonModal
          title={
            confirmAction.kind === "approve"
              ? "Approve Threat URL"
              : confirmAction.kind === "delete"
                ? "Delete Threat URL"
                : "Reject Threat URL"
          }
          subtitle={confirmAction.item.url}
          description={
            confirmAction.kind === "approve"
              ? "This URL will be published to the global Detection List for all users."
              : confirmAction.kind === "delete"
                ? "This URL will be permanently removed from the Detection List."
                : "This detection will be rejected and not added to the Detection List."
          }
          tone={confirmAction.kind === "approve" ? "green" : "red"}
          confirmLabel={
            confirmAction.kind === "approve" ? "Approve & Add" : confirmAction.kind === "delete" ? "Delete" : "Reject"
          }
          busy={busy}
          onConfirm={(r) => executeAction(r)}
          onCancel={() => setConfirmAction(null)}
        />
      ) : confirmAction ? (
        <ConfirmDialog
          title={
            confirmAction.kind === "approve"
              ? "Approve & Add to Detection List?"
              : confirmAction.kind === "delete"
                ? "Delete Threat URL?"
                : "Reject Detection?"
          }
          tone={confirmAction.kind === "approve" ? "green" : "red"}
          confirmLabel={
            confirmAction.kind === "approve" ? "Approve" : confirmAction.kind === "delete" ? "Delete" : "Reject"
          }
          busy={busy}
          onConfirm={() => executeAction()}
          onCancel={() => setConfirmAction(null)}
        >
          <p className="font-mono mb-2 break-all">{confirmAction.item.url}</p>
          {confirmAction.kind === "approve" && isFrontPage(confirmAction.item.url) && (
            <ScopeChoice value={scope} onChange={setScope} />
          )}
          <p>
            {confirmAction.kind === "approve"
              ? "This URL will be immediately added to the global Detection List."
              : confirmAction.kind === "delete"
                ? "This entry will be permanently deleted."
                : "This URL will be marked as rejected."}
          </p>
        </ConfirmDialog>
      ) : null}
    </div>
  );
}
