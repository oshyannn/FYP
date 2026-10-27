import type { ApiResult } from "./types";

// All requests go through the Electron main process: it adds the login token and talks to the backend.
export const api = {
  get: (path: string) => window.sb.api("GET", path),
  post: (path: string, body?: unknown) => window.sb.api("POST", path, body),
  del: (path: string) => window.sb.api("DELETE", path),
};

export function problem(res: ApiResult): { message: string; fields: Record<string, string> } {
  const e = res.data?.error;
  return {
    message: e?.message ?? "Something went wrong. Please try again.",
    fields: e?.fields ?? {},
  };
}
