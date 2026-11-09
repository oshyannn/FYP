// Types for the Saved URLs, Site settings and Detection Lists screens.
import type { Level } from "./analysis";

export interface SavedUrl {
  id: string;
  url: string;
  domain: string;
  title: string | null;
  note: string | null;
  risk_level: Level;
  risk_score: number;
  checked_at: string | null;
  saved_at: string;
}

export interface SiteRule {
  id: string;
  host: string;
  rule: "allow" | "block";
  note: string | null;
  created_at: string;
}

export type ListKind = "trusted" | "blocked" | "feed" | "adult" | "shared";

export interface ListItem {
  item: string;
  source: string;
  detail: string | null;
  level: Level | null;
  score: number | null;
  added_at: string | null;
}

export const LIST_TABS: { kind: ListKind; label: string; help: string }[] = [
  { kind: "trusted", label: "Trusted", help: "Websites SafeBrowse treats as safe: the top sites (Tranco) plus the manual whitelist." },
  { kind: "blocked", label: "Blocked", help: "Manual blacklist plus the threats approved by an administrator (Global Threat List)." },
  { kind: "feed", label: "Threat feeds", help: "Exact phishing and malware addresses from OpenPhish, URLhaus and PhishTank." },
  { kind: "adult", label: "Restricted", help: "Adult-content domains. The list is very large, so it can only be searched." },
  { kind: "shared", label: "Shared hosts", help: "Public hosting platforms. They are never trusted by domain, each address is checked on its own." },
];
