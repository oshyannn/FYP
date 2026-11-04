import { useCallback, useEffect, useState } from "react";
import { api, problem } from "../../../api";
import Badge from "../../../components/Badge";
import Pager from "../../../components/Pager";
import { Alert } from "../../../components/ui";
import { accountStatusLabel, accountStatusTone, displayName, roleLabel, roleTone, USERS_PER_PAGE } from "../../../lib/admin";
import type { AdminUser, StaffRole } from "../../../lib/admin";
import { shortDate } from "../../../lib/approvals";
import ManageUserModal from "./ManageUserModal";

interface Props {
  role: StaffRole;
  onSessionEnd: () => void;
}

type Tab = "accounts" | "deleted";

const selectCls = "px-3.5 py-2 border border-slate-300 rounded-lg text-sm bg-white text-slate-700 focus:outline-none focus:border-[#1e3a5f]";

// Administrator: users, employers and administrators. Employer: users only.
// Deleted accounts are on their own tab and read-only.
export default function UserManagement({ role, onSessionEnd }: Props) {
  const admin = role === "admin";
  const [tab, setTab] = useState<Tab>("accounts");
  const [search, setSearch] = useState("");
  const [q, setQ] = useState(""); // the search text, applied 300 ms after typing stops
  const [roleFilter, setRoleFilter] = useState("");
  const [status, setStatus] = useState("");
  const [page, setPage] = useState(1);
  const [rows, setRows] = useState<AdminUser[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [selected, setSelected] = useState<AdminUser | null>(null);

  useEffect(() => {
    const t = window.setTimeout(() => {
      setQ(search.trim());
      setPage(1);
    }, 300);
    return () => window.clearTimeout(t);
  }, [search]);

  const load = useCallback(async () => {
    setLoading(true);
    const qs = new URLSearchParams({ page: String(page), per_page: String(USERS_PER_PAGE) });
    if (q) qs.set("search", q);
    if (admin && roleFilter) qs.set("role", roleFilter);
    if (tab === "deleted") qs.set("tab", "deleted");
    else if (status) qs.set("status", status);
    const res = await api.get(`/api/staff/users?${qs.toString()}`);
    setLoading(false);
    if (res.status === 401) return onSessionEnd();
    if (res.status !== 200) return setError(problem(res).message);
    setError("");
    setRows(res.data.users as AdminUser[]);
    setTotal(res.data.total as number);
  }, [q, roleFilter, status, tab, page, admin]);

  useEffect(() => {
    load();
  }, [load]);

  const tabs: [Tab, string][] = [
    ["accounts", "Accounts"],
    ["deleted", "Deleted"],
  ];

  return (
    <div className="max-w-5xl space-y-5">
      <div>
        <h2 className="text-xl font-bold text-slate-900">User Management</h2>
        <p className="text-slate-500 text-sm mt-0.5">{admin ? "Manage user accounts and permissions." : "Manage user accounts."}</p>
      </div>

      {error && <Alert kind="error">{error}</Alert>}
      {notice && <Alert kind="success">{notice}</Alert>}

      <div className="flex border-b border-slate-200" role="tablist">
        {tabs.map(([key, label]) => (
          <button
            key={key}
            role="tab"
            aria-selected={tab === key}
            onClick={() => {
              setTab(key);
              setPage(1);
              setNotice("");
            }}
            className={`px-4 py-2.5 text-sm font-medium border-b-2 -mb-px transition-colors ${tab === key ? "border-[#1e3a5f] text-[#1e3a5f]" : "border-transparent text-slate-500 hover:text-slate-700"}`}
          >
            {label}
          </button>
        ))}
      </div>

      <div className="flex flex-wrap gap-3">
        <input
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          aria-label="Search user"
          maxLength={100}
          placeholder="Search user..."
          className="flex-1 min-w-48 px-3.5 py-2 border border-slate-300 rounded-lg text-sm placeholder-slate-400 bg-white focus:outline-none focus:border-[#1e3a5f] focus:ring-2 focus:ring-[#1e3a5f]/10"
        />
        {admin && (
          <select
            value={roleFilter}
            onChange={(e) => {
              setRoleFilter(e.target.value);
              setPage(1);
            }}
            aria-label="Filter by role"
            className={selectCls}
          >
            <option value="">All Roles</option>
            <option value="user">User</option>
            <option value="employer">Employer</option>
            <option value="admin">Admin</option>
          </select>
        )}
        {tab === "accounts" && (
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
            <option value="active">Active</option>
            <option value="inactive">Inactive</option>
            <option value="pending">Pending</option>
          </select>
        )}
      </div>

      <div className="bg-white rounded-xl border border-slate-200 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="text-xs text-slate-500 bg-slate-50 border-b border-slate-200">
                {["Name", "Email", "Role", "Status", "Registration Date", "Action"].map((h) => (
                  <th key={h} className="text-left px-5 py-3 font-medium">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {rows.map((row) => (
                <tr key={row.id} className="hover:bg-slate-50 transition-colors">
                  <td className="px-5 py-3.5 text-sm font-medium text-slate-800">
                    {displayName(row)}
                    {row.is_self && <span className="ml-2 text-xs font-normal text-slate-400">(you)</span>}
                  </td>
                  <td className="px-5 py-3.5 text-sm text-slate-600">{row.email}</td>
                  <td className="px-5 py-3.5">{admin ? <Badge tone={roleTone(row.role)}>{roleLabel(row.role)}</Badge> : <span className="text-sm text-slate-600">{roleLabel(row.role)}</span>}</td>
                  <td className="px-5 py-3.5">
                    <Badge tone={accountStatusTone(row.status)}>{accountStatusLabel(row.status)}</Badge>
                  </td>
                  <td className="px-5 py-3.5 text-sm text-slate-500 whitespace-nowrap">{shortDate(row.created_at)}</td>
                  <td className="px-5 py-3.5">
                    <button
                      onClick={() => {
                        setNotice("");
                        setSelected(row);
                      }}
                      className="text-[#1e3a5f] text-sm font-medium hover:underline"
                    >
                      {row.actions.edit || row.actions.deactivate || row.actions.activate ? "Manage" : "View"}
                    </button>
                  </td>
                </tr>
              ))}
              {rows.length === 0 && (
                <tr>
                  <td colSpan={6} className="px-5 py-10 text-center text-slate-400 text-sm">
                    {loading ? "Loading…" : tab === "deleted" ? "No deleted accounts." : "No accounts found."}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
        <Pager page={page} perPage={USERS_PER_PAGE} total={total} onPage={setPage} />
      </div>

      {selected && (
        <ManageUserModal
          key={selected.id}
          user={selected}
          onClose={() => setSelected(null)}
          onSessionEnd={onSessionEnd}
          onChanged={(message) => {
            setNotice(message);
            load();
          }}
        />
      )}
    </div>
  );
}
