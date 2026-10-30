import { API_BASE } from "./config";
import { clearAuth, setAuth } from "./store";
import type { Auth, Status, Verdict } from "./types";

export class ApiError extends Error {
  constructor(
    public code: string,
    message: string,
    public status = 0,
  ) {
    super(message);
  }
}

const OFFLINE = "Can't reach the SafeBrowse server. Make sure the backend is running, then try again.";

async function call(path: string, init: RequestInit = {}, token?: string): Promise<any> {
  let res: Response;
  try {
    res = await fetch(API_BASE + path, {
      ...init,
      headers: {
        "Content-Type": "application/json",
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
    });
  } catch {
    throw new ApiError("offline", OFFLINE);
  }
  let body: any = null;
  try {
    body = await res.json();
  } catch {}
  if (!res.ok) {
    const e = body?.error ?? {};
    throw new ApiError(e.code ?? "error", e.message ?? body?.message ?? `Request failed (${res.status}).`, res.status);
  }
  return body;
}

function deviceName(): string {
  const ua = navigator.userAgent;
  const os = /Windows/.test(ua) ? "Windows" : /Mac OS/.test(ua) ? "macOS" : /Linux/.test(ua) ? "Linux" : "";
  const br = /Edg\//.test(ua) ? "Edge" : /OPR\//.test(ua) ? "Opera" : /Chrome\//.test(ua) ? "Chrome" : "Browser";
  return `${br} extension${os ? " on " + os : ""}`;
}

/** Exchange the code shown in the desktop app for this extension's own token. The password is never used here. */
export async function pair(code: string): Promise<Auth> {
  const r = await call("/api/extension/pair", {
    method: "POST",
    body: JSON.stringify({ code, device_name: deviceName() }),
  });
  const auth: Auth = { token: r.token, user: r.user ?? {}, pairedAt: Date.now() };
  await setAuth(auth);
  return auth;
}

/** true = token still valid, false = rejected (stored login is removed). Network problems keep the login. */
export async function checkSession(token: string): Promise<boolean> {
  try {
    await call("/api/me", {}, token);
    return true;
  } catch (e) {
    if (e instanceof ApiError && e.status === 401) {
      await clearAuth();
      return false;
    }
    return true;
  }
}

export async function disconnect(token: string): Promise<void> {
  try {
    await call("/api/auth/logout", { method: "POST" }, token);
  } catch {}
  await clearAuth();
}

// ---- scanning goes through background.js (it owns the token, the cache and the history)
interface ScanOpts {
  force?: boolean;
  record?: boolean;
  kind?: "auto" | "manual";
}

export async function scan(url: string, opts: ScanOpts = {}): Promise<Verdict> {
  const res: { ok: boolean; verdict?: Verdict; error?: { code: string; message: string } } | undefined =
    await chrome.runtime.sendMessage({ type: "scan", url, ...opts });
  if (!res) throw new ApiError("offline", "The extension is still starting. Try again in a moment.");
  if (!res.ok || !res.verdict) throw new ApiError(res.error?.code ?? "error", res.error?.message ?? "Scan failed.");
  return res.verdict;
}

/** Open the SafeBrowse desktop app on a page (safebrowse://history). background.js does it and closes the empty tab Chrome leaves. */
export const openApp = (page: "history" | "scanner" | "dashboard" = "history") => chrome.runtime.sendMessage({ type: "open-app", page });

// ---- helpers shared by screens
export interface Target {
  tabId?: number;
  url: string; // the site being shown (for a warning page: the site that was blocked)
  onWarningPage: boolean;
  scannable: boolean;
}

export function isScannable(raw: string): boolean {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    return false;
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") return false;
  const h = u.hostname;
  if (h === "localhost" || h === "127.0.0.1" || h === "::1" || h === "[::1]") return false;
  if (/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(h)) return false;
  return h.includes(".");
}

export async function currentTarget(): Promise<Target> {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  let url = tab?.url ?? "";
  let onWarningPage = false;
  for (const page of ["blocked.html", "checking.html"]) {
    if (url.startsWith(chrome.runtime.getURL(page))) {
      onWarningPage = true;
      url = new URL(url).searchParams.get("url") ?? "";
    }
  }
  return { tabId: tab?.id, url, onWarningPage, scannable: isScannable(url) };
}

export const statusLabel = (s: Status) => (s === "safe" ? "SAFE" : s === "suspicious" ? "SUSPICIOUS" : s === "malicious" ? "MALICIOUS" : "UNKNOWN");

export function hostOf(url: string): string {
  try {
    return new URL(url).hostname.replace(/^www\./, "");
  } catch {
    return url;
  }
}

export const clock = (ts: number) => new Date(ts).toLocaleTimeString([], { hour: "numeric", minute: "2-digit" });
export const stamp = (ts: number) => new Date(ts).toLocaleString([], { dateStyle: "medium", timeStyle: "short" });
