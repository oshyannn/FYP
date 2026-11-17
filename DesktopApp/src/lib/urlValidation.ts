export interface ParsedUrlInfo {
  valid: boolean;
  error: string;
  host: string;
  path: string;
  scope: "domain" | "specific_page";
  normalized: string;
}

const HOST_RE = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$/;

/**
 * Validates a URL or domain input and determines whether it covers the full domain
 * (e.g. "example.com" or "https://example.com/") or a specific page ("example.com/login").
 */
export function validateUrlInput(rawInput: string): ParsedUrlInfo {
  const raw = (rawInput || "").trim();
  if (!raw) {
    return { valid: false, error: "Enter a website URL or domain.", host: "", path: "", scope: "domain", normalized: "" };
  }
  if (raw.length > 2048 || /[\s\x00-\x1f]/.test(raw)) {
    return { valid: false, error: "URL contains invalid characters or spaces.", host: "", path: "", scope: "domain", normalized: "" };
  }
  try {
    const withScheme = raw.includes("://") ? raw : `https://${raw}`;
    const u = new URL(withScheme);
    if (u.protocol !== "http:" && u.protocol !== "https:") {
      return { valid: false, error: "Only http and https URLs are supported.", host: "", path: "", scope: "domain", normalized: "" };
    }
    const host = u.hostname.toLowerCase().replace(/\.$/, "");
    if (!host || host.length > 253 || !HOST_RE.test(host)) {
      return { valid: false, error: "Enter a valid domain name (e.g. example.com).", host: "", path: "", scope: "domain", normalized: "" };
    }
    const segs = u.pathname.split("/").filter(Boolean);
    if (segs.some((s) => s === "." || s === "..")) {
      return { valid: false, error: "Invalid path segments in URL.", host: "", path: "", scope: "domain", normalized: "" };
    }
    const path = segs.length > 0 ? "/" + segs.join("/").toLowerCase() : "";
    const scope = path ? "specific_page" : "domain";
    const normalized = `${u.protocol}//${host}${u.port ? `:${u.port}` : ""}${path || "/"}`;
    return { valid: true, error: "", host, path, scope, normalized };
  } catch {
    return { valid: false, error: "Enter a valid URL (e.g. https://example.com).", host: "", path: "", scope: "domain", normalized: "" };
  }
}

export function normalizeUrlKey(raw: string): string {
  const res = validateUrlInput(raw);
  return res.valid ? `${res.host}${res.path}` : raw.trim().toLowerCase();
}
