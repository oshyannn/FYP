type Status = "SAFE" | "SUSPICIOUS" | "MALICIOUS" | "Blocked" | "Pending" | "Active" | "Inactive" | "In Review" | "Responded" | "Closed" | "Approved" | "Rejected" | "Phishing" | "Malware" | string;

export default function StatusBadge({ status }: { status: Status }) {
  const s = status.toUpperCase();
  let cls = "bg-slate-100 text-slate-700";
  if (s === "SAFE" || s === "ACTIVE" || s === "APPROVED") cls = "bg-green-50 text-green-700 border border-green-200";
  else if (s === "SUSPICIOUS" || s === "IN REVIEW" || s === "PENDING") cls = "bg-amber-50 text-amber-700 border border-amber-200";
  else if (s === "MALICIOUS" || s === "BLOCKED" || s === "INACTIVE" || s === "REJECTED") cls = "bg-red-50 text-red-700 border border-red-200";
  else if (s === "RESPONDED" || s === "CLOSED") cls = "bg-blue-50 text-blue-700 border border-blue-200";
  else if (s === "PHISHING") cls = "bg-orange-50 text-orange-700 border border-orange-200";
  else if (s === "MALWARE") cls = "bg-red-50 text-red-700 border border-red-200";

  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${cls}`}>
      {status}
    </span>
  );
}
