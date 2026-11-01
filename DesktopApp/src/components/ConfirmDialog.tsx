import type { ReactNode } from "react";

interface Props {
  title: string;
  children: ReactNode;
  confirmLabel?: string;
  tone: "green" | "red";
  busy?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}

// A small "are you sure?" card that sits above any other dialog.
export default function ConfirmDialog({ title, children, confirmLabel = "Confirm", tone, busy, onConfirm, onCancel }: Props) {
  return (
    <div className="fixed inset-0 z-[60] bg-black/50 flex items-center justify-center p-4" role="alertdialog" aria-modal="true" aria-label={title}>
      <div className="bg-white rounded-2xl p-6 max-w-sm w-full shadow-xl">
        <h3 className="font-semibold text-slate-900 mb-2">{title}</h3>
        <div className="text-slate-500 text-sm mb-5">{children}</div>
        <div className="flex gap-3">
          <button onClick={onCancel} className="flex-1 border border-slate-300 text-slate-700 py-2.5 rounded-lg text-sm font-medium hover:bg-slate-50">
            Cancel
          </button>
          <button
            onClick={onConfirm}
            disabled={busy}
            className={`flex-1 py-2.5 rounded-lg text-sm font-semibold text-white disabled:opacity-60 ${tone === "green" ? "bg-green-600 hover:bg-green-700" : "bg-red-600 hover:bg-red-700"}`}
          >
            {busy ? "Please wait…" : confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}
