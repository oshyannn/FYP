// All persistent data of the popup lives behind this file.
//
// TODAY: chrome.storage.local (settings and the pairing token are per browser profile).
// Scan history is deliberately NOT stored here: every scan is saved to the signed-in account by background.js and is read
// in the desktop app (which needs a login), so nobody using this browser can read the list of visited websites.
// LATER (Supabase): replace the bodies of getSettings / saveSettings with calls to the backend so settings follow the user.
import type { Auth, Settings } from "./types";

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

/** Calls cb whenever settings or auth change (also when background.js writes them). */
export function onStoreChange(cb: () => void): () => void {
  const fn = (_: unknown, area: string) => area === "local" && cb();
  chrome.storage.onChanged.addListener(fn);
  return () => chrome.storage.onChanged.removeListener(fn);
}
