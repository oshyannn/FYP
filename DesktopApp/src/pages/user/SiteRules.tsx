import { useCallback, useEffect, useState } from "react";
import { api, problem } from "../../api";
import Badge from "../../components/Badge";
import ConfirmDialog from "../../components/ConfirmDialog";
import { Alert } from "../../components/ui";
import { shortDate } from "../../lib/approvals";

interface SiteRule {
  id: string;
  host: string;
  rule: "allow" | "block";
  note: string | null;
  created_at: string;
}

interface Props {
  onSessionEnd: () => void;
}

// The person's own "always allow" / "always block" choices (table url_lists). The browser extension applies them on every visit.
export default function SiteRules({ onSessionEnd }: Props) {
  const [rules, setRules] = useState<SiteRule[]>([]);
  const [host, setHost] = useState("");
  const [rule, setRule] = useState<"allow" | "block">("block");
  const [fieldError, setFieldError] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [loading, setLoading] = useState(true);
  const [adding, setAdding] = useState(false);
  const [target, setTarget] = useState<SiteRule | null>(null);
  const [removing, setRemoving] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    const res = await api.get("/api/site-rules");
    setLoading(false);
    if (res.status === 401) return onSessionEnd();
    if (res.status !== 200) return setError(problem(res).message);
    setError("");
    setRules(res.data.rules as SiteRule[]);
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  async function add() {
    const value = host.trim();
    if (!value || adding) return;
    setAdding(true);
    setError("");
    setFieldError("");
    setNotice("");
    const res = await api.put("/api/site-rules", { host: value, rule });
    setAdding(false);
    if (res.status === 401) return onSessionEnd();
    if (res.status === 200) {
      setHost("");
      setNotice(`${res.data.rule.host} is now ${rule === "block" ? "always blocked" : "always allowed"}. The browser extension picks it up within a minute.`);
      return load();
    }
    if (res.status === 429) return setError("Too many requests. Wait a moment and try again.");
    const p = problem(res);
    if (res.status === 400) setFieldError(p.fields.host ?? p.message);
    else setError(p.message);
  }

  async function remove() {
    if (!target || removing) return;
    setRemoving(true);
    const res = await api.del(`/api/site-rules/${target.id}`);
    setRemoving(false);
    if (res.status === 401) return onSessionEnd();
    setTarget(null);
    if (res.status !== 200 && res.status !== 404) return setError(problem(res).message);
    load();
  }

  return (
    <div className="max-w-3xl space-y-5">
      <div>
        <h2 className="text-xl font-bold text-slate-900">Site Rules</h2>
        <p className="text-slate-500 text-sm mt-0.5">
          Websites you always allow or always block. A rule for example.com also covers its subdomains. You can also set one from the browser extension, Site settings.
        </p>
      </div>

      {error && <Alert kind="error">{error}</Alert>}
      {notice && <Alert kind="success">{notice}</Alert>}

      <div className="bg-white rounded-xl border border-slate-200 p-5">
        <h3 className="font-semibold text-slate-800 mb-3">Add a rule</h3>
        <div className="flex gap-3">
          <input
            value={host}
            maxLength={2048}
            onChange={(e) => {
              setHost(e.target.value);
              setFieldError("");
            }}
            onKeyDown={(e) => e.key === "Enter" && add()}
            aria-label="Website"
            aria-invalid={!!fieldError}
            placeholder="Enter URL or domain, e.g. example.com"
            className={`flex-1 px-3.5 py-2.5 border rounded-lg text-sm placeholder-slate-400 focus:outline-none focus:ring-2 ${fieldError ? "border-red-400 focus:ring-red-100" : "border-slate-300 focus:border-[#1e3a5f] focus:ring-[#1e3a5f]/10"}`}
          />
          <select
            value={rule}
            onChange={(e) => setRule(e.target.value as "allow" | "block")}
            aria-label="Rule"
            className="px-3 py-2.5 border border-slate-300 rounded-lg text-sm bg-white"
          >
            <option value="block">Always block</option>
            <option value="allow">Always allow</option>
          </select>
          <button
            onClick={add}
            disabled={adding || !host.trim()}
            className="bg-[#1e3a5f] text-white px-5 py-2.5 rounded-lg text-sm font-semibold hover:bg-[#162d4a] disabled:opacity-50 transition-colors"
          >
            {adding ? "Adding…" : "+ Add"}
          </button>
        </div>
        {fieldError && <p className="text-red-500 text-xs mt-1.5">{fieldError}</p>}
        {rule === "allow" && (
          <p className="text-slate-400 text-xs mt-2">An always-allowed website never gets a warning, even if SafeBrowse finds it dangerous.</p>
        )}
      </div>

      <div className="bg-white rounded-xl border border-slate-200 overflow-hidden">
        <div className="px-5 py-4 border-b border-slate-100">
          <h3 className="font-semibold text-slate-800">Your rules ({rules.length})</h3>
        </div>
        <ul className="divide-y divide-slate-100">
          {rules.map((r) => (
            <li key={r.id} className="px-5 py-3.5 flex items-center gap-4">
              <Badge tone={r.rule === "block" ? "red" : "green"}>{r.rule === "block" ? "Blocked" : "Allowed"}</Badge>
              <div className="min-w-0 flex-1">
                <p className="text-sm font-mono text-slate-700 break-all">{r.host}</p>
                <p className="text-xs text-slate-400 mt-0.5">Added {shortDate(r.created_at)}</p>
              </div>
              <button onClick={() => setTarget(r)} className="text-red-500 text-sm font-medium hover:underline">
                Remove
              </button>
            </li>
          ))}
          {rules.length === 0 && (
            <li className="px-5 py-10 text-center text-slate-400 text-sm">{loading ? "Loading…" : "No rules yet."}</li>
          )}
        </ul>
      </div>

      {target && (
        <ConfirmDialog title="Remove this rule?" tone="red" confirmLabel="Remove" busy={removing} onConfirm={remove} onCancel={() => setTarget(null)}>
          <p className="font-mono mb-1 break-all">{target.host}</p>
          <p>SafeBrowse will check this website like any other from now on.</p>
        </ConfirmDialog>
      )}
    </div>
  );
}
