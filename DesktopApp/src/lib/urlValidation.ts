export interface ParsedUrlInfo {
  valid: boolean;
  error: string;
  host: string;
  path: string;
  scope: "domain" | "specific_page";
  normalized: string;
}

const HOST_RE = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$/;
const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

function classifyIpv4(host: string): "public" | "private" | "invalid" | "not_ip" {
  const m = IPV4_RE.exec(host);
  if (!m) return "not_ip";
  const octets = m.slice(1).map(Number);
  if (octets.some((n) => n < 0 || n > 255)) return "invalid";
  const [a, b] = octets;
  if (
    a === 0 ||
    a === 10 ||
    a === 127 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    a >= 224
  ) {
    return "private";
  }
  return "public";
}

/**
 * Validates a URL, domain, or public IPv4 input and determines whether it covers the full host
 * (e.g. "example.com" or "http://45.133.1.10/") or a specific page ("example.com/login").
 */
export function validateUrlInput(rawInput: string): ParsedUrlInfo {
  const raw = (rawInput || "").trim();
  if (!raw) {
    return { valid: false, error: "Enter a website URL, domain, or public IP address.", host: "", path: "", scope: "domain", normalized: "" };
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
    const ipState = classifyIpv4(host);
    if (ipState === "private") {
      return { valid: false, error: "Private or local IP addresses cannot be scanned. Enter a public IP address or domain.", host: "", path: "", scope: "domain", normalized: "" };
    }
    if (ipState === "invalid") {
      return { valid: false, error: "Enter a valid public IP address or domain name.", host: "", path: "", scope: "domain", normalized: "" };
    }
    if (ipState === "not_ip" && (!host || host.length > 253 || !HOST_RE.test(host))) {
      return { valid: false, error: "Enter a valid domain name or public IP address (e.g. example.com).", host: "", path: "", scope: "domain", normalized: "" };
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
