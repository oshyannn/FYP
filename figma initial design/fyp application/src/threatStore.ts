// Shared data types for the threat URL submission flow

export interface ThreatEntry {
  id: number;
  url: string;
  type: string;
  score: number;
  status: string;
  date: string;
  source: string;
  notes: string;
}

export interface PendingSubmission {
  id: number;
  url: string;
  type: string;
  score: number;
  notes: string;
  source: string;
  submittedBy: string;
  submittedDate: string;
  reviewStatus: "Pending" | "Approved" | "Rejected";
  reviewNote: string;
}

export const initialThreats: ThreatEntry[] = [
  { id: 1, url: "fake-login.com", type: "Phishing", score: 96, status: "Blocked", date: "31 Aug 2026", source: "AI Detection", notes: "Mimics a bank login page to steal credentials." },
  { id: 2, url: "malware-site.com", type: "Malware", score: 98, status: "Blocked", date: "30 Aug 2026", source: "Security API", notes: "Distributes ransomware via drive-by download." },
  { id: 3, url: "phish-bank.net", type: "Phishing", score: 93, status: "Blocked", date: "30 Aug 2026", source: "User Report", notes: "Fake banking portal harvesting login credentials." },
  { id: 4, url: "virus-download.xyz", type: "Malware", score: 99, status: "Blocked", date: "29 Aug 2026", source: "AI Detection", notes: "Hosts executable files disguised as software updates." },
  { id: 5, url: "free-giveaway.top", type: "Suspicious", score: 72, status: "SUSPICIOUS", date: "29 Aug 2026", source: "URL Analysis", notes: "Suspicious prize scam with data collection forms." },
];

export const initialPending: PendingSubmission[] = [
  {
    id: 101,
    url: "credential-harvest.net",
    type: "Phishing",
    score: 91,
    notes: "Spotted this URL in a phishing email campaign targeting our employees. Looks like a fake Microsoft login page.",
    source: "Employer Report",
    submittedBy: "employer@safebrowse.com",
    submittedDate: "31 Aug 2026, 08:45 AM",
    reviewStatus: "Pending",
    reviewNote: "",
  },
];
