import { useCallback, useEffect, useState } from "react";
import { api, problem } from "../../api";
import Badge from "../../components/Badge";
import ConfirmDialog from "../../components/ConfirmDialog";
import { Alert } from "../../components/ui";
import type { SiteRule } from "../../lib/sites";

const day = (iso: string) => new Date(iso).toLocaleDateString(undefined, { day: "numeric", month: "short", year: "numeric" });

// The person's own decisions: websites that are always allowed or always blocked, whatever the detector says.
// (Temporary choices from the warning page - this visit, 1 hour, until the browser closes - live in the extension only.)
export default function SiteSettings({ onSessionEnd }: { onSessionEnd: () => void }) {
  const [rules, setRules] = useState<SiteRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [host, setHost] = useState("");
  const [mode, setMode] = useState<"allow" | "block">("block");
  const [adding, setAdding] = useState(false);
  const [pendingAllow, setPendingAllow] = useState<string | null>(null);
  const [target, setTarget] = useState<SiteRule | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    const res = await api.get("/api/site-rules");
    setLoading(false);
    if (res.status === 401) return onSessionEnd();
    if (res.status !== 200) return setError(problem(res).message);
    setRules(res.data.rules as SiteRule[]);
  }, [onSessionEnd]);

  useEffect(() => {
    load();
  }, [load]);

  async function put(h: string, rule: "allow" | "block") {
    setBusy(true);
    setError("");
    setNotice("");
    const res = await api.put("/api/site-rules", { host: h, rule });
    setBusy(false);
    setPendingAllow(null);
    if (res.status === 401) return onSessionEnd();
    if (res.status !== 200) return setError(problem(res).message);
    setNotice(`${(res.data.rule as SiteRule).host}: ${rule === "allow" ? "always allowed" : "always blocked"}.`);
    setAdding(false);
    setHost("");
    load();
  }

  function submit() {
    const h = host.trim();
    if (!h) return;
    if (mode === "allow") setPendingAllow(h);
    else {
      setAdding(true);
      put(h, "block");
    }
  }

  async function remove() {
    if (!target) return;
    setBusy(true);
    const res = await api.del(`/api/site-rules/${target.id}`);
    setBusy(false);
    setTarget(null);
    if (res.status === 401) return onSessionEnd();
    if (res.status !== 200 && res.status !== 404) return setError(problem(res).message);
    load();
  }

  const cls = "px-3.5 py-2.5 border border-slate-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:border-[#1e3a5f] focus:ring-[#1e3a5f]/10";

  return (
    <div className="max-w-3xl space-y-5">
      <div>
        <h2 className="text-xl font-bold text-slate-900">Site settings</h2>
        <p className="text-slate-500 text-sm mt-0.5">
          Your own decision for a website. It applies to the site and its subdomains and is used before any other check. Removing a rule brings the
          normal warning back.
        </p>
      </div>
      {error && <Alert kind="error">{error}</Alert>}
      {notice && <Alert kind="success">{notice}</Alert>}

      <div className="bg-white rounded-xl border border-slate-200 p-5">
        <h3 className="font-semibold text-slate-800 mb-3">Add a rule</h3>
        <div className="flex gap-3">
          <input
            value={host}
            maxLength={253}
            onChange={(e) => setHost(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && submit()}
            aria-label="Website"
            placeholder="example.com"
            className={`flex-1 ${cls}`}
          />
          <select value={mode} onChange={(e) => setMode(e.target.value as "allow" | "block")} aria-label="Decision" className={cls}>
            <option value="block">Always block</option>
            <option value="allow">Always allow</option>
          </select>
          <button onClick={submit} disabled={busy || adding || !host.trim()} className="bg-[#1e3a5f] text-white px-5 py-2.5 rounded-lg text-sm font-semibold hover:bg-[#162d4a] disabled:opacity-50">
            Save
          </button>
        </div>
      </div>

      <div className="bg-white rounded-xl border border-slate-200 overflow-hidden">
        <div className="px-5 py-4 border-b border-slate-100">
          <h3 className="font-semibold text-slate-800">Your rules ({rules.length})</h3>
        </div>
        <ul className="divide-y divide-slate-100">
          {rules.map((r) => (
            <li key={r.id} className="px-5 py-3.5 flex items-center justify-between gap-4">
              <div className="min-w-0">
                <p className="text-sm font-mono text-slate-700 break-all">{r.host}</p>
                <p className="text-xs text-slate-400 mt-0.5">Since {day(r.created_at)}</p>
              </div>
              <div className="flex items-center gap-4 shrink-0">
                <Badge tone={r.rule === "allow" ? "green" : "red"}>{r.rule === "allow" ? "Always allow" : "Always block"}</Badge>
                <button
                  onClick={() => (r.rule === "allow" ? put(r.host, "block") : setPendingAllow(r.host))}
                  disabled={busy}
                  className="text-sm font-medium text-[#1e3a5f] hover:underline disabled:opacity-50"
                >
                  {r.rule === "allow" ? "Block instead" : "Allow instead"}
                </button>
                <button onClick={() => setTarget(r)} className="text-red-500 text-sm font-medium hover:underline">Remove</button>
              </div>
            </li>
          ))}
          {rules.length === 0 && <li className="px-5 py-10 text-center text-slate-400 text-sm">{loading ? "Loading…" : "No rules yet. Choices made on the warning page appear here."}</li>}
        </ul>
      </div>

      {pendingAllow && (
        <ConfirmDialog title="Always allow this website?" tone="red" confirmLabel="Always allow" busy={busy} onConfirm={() => put(pendingAllow, "allow")} onCancel={() => setPendingAllow(null)}>
          <p className="font-mono mb-1 break-all">{pendingAllow}</p>
          <p>SafeBrowse will no longer warn you about this website, even if it is on the threat list or detected as malicious. You can remove the rule here at any time.</p>
        </ConfirmDialog>
      )}
      {target && (
        <ConfirmDialog title="Remove this rule?" tone="red" confirmLabel="Remove" busy={busy} onConfirm={remove} onCancel={() => setTarget(null)}>
          <p className="font-mono mb-1 break-all">{target.host}</p>
          <p>The normal detection and warning apply again.</p>
        </ConfirmDialog>
      )}
    </div>
  );
}
