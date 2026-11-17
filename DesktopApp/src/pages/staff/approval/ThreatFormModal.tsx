import { useState } from "react";
import { api, problem } from "../../../api";
import Modal from "../../../components/Modal";
import { Alert } from "../../../components/ui";
import { THREAT_TYPE_OPTIONS, isFrontPage } from "../../../lib/threats";
import type { MatchScope, ThreatItem } from "../../../lib/threats";
import { validateUrlInput } from "../../../lib/urlValidation";
import type { StaffRole } from "../../../lib/admin";

interface Props {
  role: StaffRole;
  /** If provided, edits an existing threat entry; otherwise creates a new one. */
  existing?: ThreatItem | null;
  onClose: () => void;
  onSaved: (message: string) => void;
  onSessionEnd: () => void;
}

const fieldCls = (bad: boolean) =>
  `w-full px-3.5 py-2.5 border rounded-lg text-sm placeholder-slate-400 focus:outline-none focus:ring-2 transition-colors ${
    bad ? "border-red-400 focus:border-red-400 focus:ring-red-100" : "border-slate-300 focus:border-[#1e3a5f] focus:ring-[#1e3a5f]/10"
  }`;

export default function ThreatFormModal({ role, existing, onClose, onSaved, onSessionEnd }: Props) {
  const isEdit = !!existing;
  const isEmployer = role === "employer";

  const [url, setUrl] = useState(existing?.url ?? "");
  const [threatType, setThreatType] = useState(existing?.threat_type ?? "phishing");
  const [isMalicious, setIsMalicious] = useState<boolean>(existing ? existing.risk_level === "malicious" : true);
  const [matchScope, setMatchScope] = useState<MatchScope>(existing?.match_scope ?? "auto");
  const [reason, setReason] = useState(existing?.notes ?? "");
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const parsed = validateUrlInput(url);

  function validate(): boolean {
    const e: Record<string, string> = {};
    if (!parsed.valid) e.url = parsed.error;
    if (isEmployer && reason.trim().length < 3) {
      e.reason = "Please provide a reason (at least 3 characters).";
    }
    setErrors(e);
    return Object.keys(e).length === 0;
  }

  async function submit() {
    if (busy || !validate()) return;
    setBusy(true);
    setError("");
    const payload = {
      url: url.trim(),
      threat_type: threatType,
      is_malicious: isMalicious,
      match_scope: isFrontPage(parsed.normalized) ? matchScope : "exact",
      ...(reason.trim() ? { notes: reason.trim(), reason: reason.trim() } : {}),
    };

    const res = isEdit
      ? await api.patch(`/api/staff/threats/${existing!.id}`, payload)
      : await api.post("/api/staff/threats", payload);

    setBusy(false);
    if (res.status === 401) return onSessionEnd();
    if (res.status === 200 || res.status === 201) {
      onSaved(isEdit ? "Threat URL updated." : `${parsed.normalized} added to the Detection List.`);
      return;
    }
    const p = problem(res);
    if (Object.keys(p.fields).length) setErrors(p.fields);
    else setError(p.message);
  }

  return (
    <Modal
      title={isEdit ? "Modify Threat URL" : "Add Threat URL"}
      subtitle={
        isEdit
          ? "Update the threat classification, severity, or URL."
          : "Add a threat URL directly to the global Detection List."
      }
      width="lg"
      onClose={onClose}
      footer={
        <>
          <button
            type="button"
            onClick={onClose}
            disabled={busy}
            className="flex-1 border border-slate-300 text-slate-700 py-2.5 rounded-lg text-sm font-medium hover:bg-slate-50"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={submit}
            disabled={busy}
            className="flex-1 bg-[#1e3a5f] text-white py-2.5 rounded-lg text-sm font-semibold hover:bg-[#162d4a] disabled:opacity-60"
          >
            {busy ? "Saving…" : isEdit ? "Save Changes" : "Add Threat URL"}
          </button>
        </>
      }
    >
      {error && <Alert kind="error">{error}</Alert>}

      <div className="space-y-4">
        <div>
          <div className="flex items-center justify-between mb-1.5">
            <label htmlFor="tf-url" className="block text-sm font-medium text-slate-700">
              URL or Domain <span className="text-red-500">*</span>
            </label>
            {url.trim() && parsed.valid && (
              <span
                className={`text-[11px] font-medium px-2 py-0.5 rounded-full ${
                  parsed.scope === "domain" ? "bg-purple-50 text-purple-700" : "bg-blue-50 text-blue-700"
                }`}
              >
                {parsed.scope === "domain" ? "Covers full domain" : "Specific page URL"}
              </span>
            )}
          </div>
          <input
            id="tf-url"
            value={url}
            maxLength={2048}
            onChange={(e) => {
              setUrl(e.target.value);
              setErrors((prev) => ({ ...prev, url: "" }));
            }}
            placeholder="https://malicious-example.com or example.com/login"
            className={`${fieldCls(!!errors.url)} font-mono`}
          />
          {errors.url && <p className="text-red-500 text-xs mt-1">{errors.url}</p>}
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div>
            <label htmlFor="tf-type" className="block text-sm font-medium text-slate-700 mb-1.5">
              Threat Category
            </label>
            <select
              id="tf-type"
              value={threatType}
              onChange={(e) => setThreatType(e.target.value)}
              className="w-full px-3.5 py-2.5 border border-slate-300 rounded-lg text-sm bg-white text-slate-700 focus:outline-none focus:border-[#1e3a5f]"
            >
              {THREAT_TYPE_OPTIONS.map(([v, l]) => (
                <option key={v} value={v}>
                  {l}
                </option>
              ))}
            </select>
          </div>

          <div>
            <span className="block text-sm font-medium text-slate-700 mb-1.5">
              Malicious Severity <span className="text-red-500">*</span>
            </span>
            <div className="grid grid-cols-2 gap-2" role="radiogroup" aria-label="Malicious severity">
              <button
                type="button"
                role="radio"
                aria-checked={isMalicious}
                onClick={() => setIsMalicious(true)}
                className={`py-2 px-3 rounded-lg text-xs font-semibold border transition-colors ${
                  isMalicious
                    ? "bg-red-50 border-red-400 text-red-700"
                    : "bg-white border-slate-300 text-slate-600 hover:bg-slate-50"
                }`}
              >
                Malicious (True)
              </button>
              <button
                type="button"
                role="radio"
                aria-checked={!isMalicious}
                onClick={() => setIsMalicious(false)}
                className={`py-2 px-3 rounded-lg text-xs font-semibold border transition-colors ${
                  !isMalicious
                    ? "bg-amber-50 border-amber-400 text-amber-700"
                    : "bg-white border-slate-300 text-slate-600 hover:bg-slate-50"
                }`}
              >
                Suspicious (False)
              </button>
            </div>
          </div>
        </div>

        {parsed.valid && isFrontPage(parsed.normalized) && (
          <div>
            <span className="block text-sm font-medium text-slate-700 mb-1.5">Match Scope</span>
            <div className="grid grid-cols-2 gap-2">
              <button
                type="button"
                onClick={() => setMatchScope("auto")}
                className={`py-2 px-3 rounded-lg text-xs font-medium border text-left ${
                  matchScope === "auto"
                    ? "bg-blue-50 border-[#1e3a5f] text-[#1e3a5f]"
                    : "bg-white border-slate-300 text-slate-600 hover:bg-slate-50"
                }`}
              >
                <div className="font-semibold">Whole domain</div>
                <div className="text-[11px] opacity-75">Blocks {parsed.host} &amp; subpages</div>
              </button>
              <button
                type="button"
                onClick={() => setMatchScope("exact")}
                className={`py-2 px-3 rounded-lg text-xs font-medium border text-left ${
                  matchScope === "exact"
                    ? "bg-blue-50 border-[#1e3a5f] text-[#1e3a5f]"
                    : "bg-white border-slate-300 text-slate-600 hover:bg-slate-50"
                }`}
              >
                <div className="font-semibold">Exact front page only</div>
                <div className="text-[11px] opacity-75">Only the root URL</div>
              </button>
            </div>
          </div>
        )}

        <div>
          <label htmlFor="tf-reason" className="block text-sm font-medium text-slate-700 mb-1.5">
            {isEmployer ? (
              <>
                Reason <span className="text-red-500">*</span>
              </>
            ) : (
              <>
                Notes <span className="text-slate-400 font-normal">(optional)</span>
              </>
            )}
          </label>
          <textarea
            id="tf-reason"
            value={reason}
            maxLength={1000}
            rows={3}
            onChange={(e) => {
              setReason(e.target.value);
              setErrors((prev) => ({ ...prev, reason: "" }));
            }}
            placeholder={
              isEmployer
                ? "Required: explain why this threat URL is being added or modified..."
                : "Optional notes about this threat..."
            }
            className={`${fieldCls(!!errors.reason)} resize-none`}
          />
          {errors.reason && <p className="text-red-500 text-xs mt-1">{errors.reason}</p>}
        </div>
      </div>
    </Modal>
  );
}
