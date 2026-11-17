import { useState } from "react";
import Modal from "./Modal";

interface Props {
  title: string;
  subtitle?: string;
  description?: string;
  confirmLabel?: string;
  tone?: "primary" | "green" | "red";
  busy?: boolean;
  onConfirm: (reason: string) => void;
  onCancel: () => void;
}

export default function EmployerReasonModal({
  title,
  subtitle,
  description,
  confirmLabel = "Confirm",
  tone = "primary",
  busy = false,
  onConfirm,
  onCancel,
}: Props) {
  const [reason, setReason] = useState("");
  const [err, setErr] = useState("");

  function submit() {
    const v = reason.trim();
    if (v.length < 3) {
      setErr("Please enter a reason (at least 3 characters).");
      return;
    }
    onConfirm(v);
  }

  const btnCls =
    tone === "red"
      ? "bg-red-600 hover:bg-red-700 text-white"
      : tone === "green"
        ? "bg-green-600 hover:bg-green-700 text-white"
        : "bg-[#1e3a5f] hover:bg-[#162d4a] text-white";

  return (
    <Modal
      title={title}
      subtitle={subtitle}
      onClose={onCancel}
      footer={
        <>
          <button
            type="button"
            onClick={onCancel}
            disabled={busy}
            className="flex-1 border border-slate-300 text-slate-700 py-2.5 rounded-lg text-sm font-medium hover:bg-slate-50"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={submit}
            disabled={busy}
            className={`flex-1 py-2.5 rounded-lg text-sm font-semibold disabled:opacity-60 ${btnCls}`}
          >
            {busy ? "Please wait…" : confirmLabel}
          </button>
        </>
      }
    >
      <div className="space-y-3">
        {description && <p className="text-sm text-slate-600">{description}</p>}
        <div>
          <label htmlFor="emp-reason" className="block text-sm font-medium text-slate-700 mb-1.5">
            Reason for this change <span className="text-red-500">*</span>
          </label>
          <textarea
            id="emp-reason"
            value={reason}
            maxLength={500}
            rows={3}
            onChange={(e) => {
              setReason(e.target.value);
              setErr("");
            }}
            placeholder="Explain why you are making this change (logged for audit)..."
            className={`w-full px-3.5 py-2.5 border rounded-lg text-sm placeholder-slate-400 focus:outline-none focus:ring-2 resize-none ${
              err
                ? "border-red-400 focus:border-red-400 focus:ring-red-100"
                : "border-slate-300 focus:border-[#1e3a5f] focus:ring-[#1e3a5f]/10"
            }`}
          />
          {err && <p className="text-red-500 text-xs mt-1">{err}</p>}
        </div>
      </div>
    </Modal>
  );
}
