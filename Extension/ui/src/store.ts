// All persistent data of the popup lives behind this file.
//
// TODAY: chrome.storage.local (history / settings / auth are per browser profile).
// LATER (Supabase): replace the bodies of getHistory / clearHistory / getSettings / saveSettings with calls to the
// backend or Supabase so history and settings follow the user across the desktop app and the extension.
// The screens and background.js only use the functions below, so nothing else has to change.
import type { Auth, HistoryRecord, Settings } from "./types";

export const DEFAULT_SETTINGS: Settings = { realtime: true, autoscan: true, blocking: true, notifications: true };

async function read<T>(key: string, fallback: T): Promise<T> {
  try {
    const v = (await chrome.storage.local.get(key))[key];
    return (v ?? fallback) as T;
  } catch {
    return fallback;
  }
}

export const getAuth = () => read<Auth | null>("auth", null);
export const setAuth = (a: Auth) => chrome.storage.local.set({ auth: a });
export const clearAuth = () => chrome.storage.local.remove("auth");

export async function getSettings(): Promise<Settings> {
  return { ...DEFAULT_SETTINGS, ...(await read<Partial<Settings>>("settings", {})) };
}
export const saveSettings = (s: Settings) => chrome.storage.local.set({ settings: s });

export const getHistory = () => read<HistoryRecord[]>("history", []);
export const clearHistory = () => chrome.storage.local.set({ history: [] });

/** Calls cb whenever history, settings or auth change (also when background.js writes them). */
export function onStoreChange(cb: () => void): () => void {
  const fn = (_: unknown, area: string) => area === "local" && cb();
  chrome.storage.onChanged.addListener(fn);
  return () => chrome.storage.onChanged.removeListener(fn);
}
