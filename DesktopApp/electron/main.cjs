"use strict";
const { app, BrowserWindow, ipcMain, safeStorage, session, Menu } = require("electron");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const DEV = process.argv.includes("--dev");
const DEV_URL = "http://127.0.0.1:5173";
const API_BASE = (process.env.SAFEBROWSE_API || "http://127.0.0.1:5000").replace(/\/+$/, "");
const PROTOCOL = "safebrowse";                       // the browser extension opens the app with safebrowse://<page>
const OPEN_PAGES = new Set(["dashboard", "history", "scanner"]);
let pendingPage = null;                              // a page requested before the window could show it

/** safebrowse://history -> "history"; anything unknown -> null (no other part of the link is ever used) */
function pageFromProtocolUrl(raw) {
  try {
    const u = new URL(raw);
    if (u.protocol !== PROTOCOL + ":") return null;
    const page = (u.hostname || u.pathname.replace(/^\/+/, "")).toLowerCase();
    return OPEN_PAGES.has(page) ? page : null;
  } catch { return null; }
}
const sessionFile = () => path.join(app.getPath("userData"), "session.bin");

// ---- authentication state lives ONLY in this process -------------------------------------------------------
let auth = null;     // { token, portal, persist }
let pending = null;  // { email, secret }: a sign-up in progress; the secret lets only THIS app be signed in by the link

const METHODS = new Set(["GET", "POST", "PATCH", "DELETE"]);
const PATH_OK = /^\/api\/[A-Za-z0-9/_-]{1,100}(\?[A-Za-z0-9=&%._~+-]{0,1200})?$/;
const NO_TOKEN = new Set([
  "/api/auth/login", "/api/staff/login", "/api/auth/register", "/api/staff/request-access",
  "/api/auth/verify-email", "/api/auth/complete-signup", "/api/auth/resend-code",
  "/api/auth/forgot-password", "/api/staff/forgot-password", "/api/auth/reset-password",
]);
const TOKEN_PATHS = new Set(["/api/auth/login", "/api/staff/login", "/api/auth/complete-signup", "/api/auth/verify-email"]);

const fail = (message) => ({ status: 0, data: { error: { code: "bad_request", message } } });
const emailOf = (b) => (b && typeof b.email === "string" ? b.email.trim().toLowerCase() : "");

// ---- optional "remember me" (user portal only): token encrypted with the operating system's key store -------------
function saveSession() {
  if (!auth || !auth.persist || !safeStorage.isEncryptionAvailable()) return;
  const blob = safeStorage.encryptString(JSON.stringify({ token: auth.token, portal: auth.portal }));
  fs.writeFileSync(sessionFile(), blob, { mode: 0o600 });
}
function clearSavedSession() {
  try { fs.unlinkSync(sessionFile()); } catch { /* nothing saved */ }
}
function loadSavedSession() {
  try {
    if (!safeStorage.isEncryptionAvailable() || !fs.existsSync(sessionFile())) return null;
    const o = JSON.parse(safeStorage.decryptString(fs.readFileSync(sessionFile())));
    return o && typeof o.token === "string" && typeof o.portal === "string" ? o : null;
  } catch { return null; }
}

async function request(method, apiPath, body, withToken) {
  const headers = { Accept: "application/json" };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (withToken && auth) headers.Authorization = "Bearer " + auth.token;
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 15000);
  try {
    const res = await fetch(API_BASE + apiPath, {
      method, headers, signal: ctrl.signal,
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    let data = null;
    try { data = await res.json(); } catch { data = null; }
    return { status: res.status, data };
  } catch {
    return { status: 0, data: { error: { code: "network", message: "Cannot reach the SafeBrowse server. Make sure the backend is running." } } };
  } finally {
    clearTimeout(timer);
  }
}

ipcMain.handle("api", async (_event, req) => {
  if (!req || typeof req !== "object") return fail("Invalid request.");
  const method = String(req.method || "").toUpperCase();
  const apiPath = String(req.path || "");
  if (!METHODS.has(method) || !PATH_OK.test(apiPath)) return fail("Invalid request.");
  const body = req.body && typeof req.body === "object" && !Array.isArray(req.body) ? { ...req.body } : undefined;

  let started = null;
  if (apiPath === "/api/auth/register" && body) {
    const secret = crypto.randomBytes(32).toString("base64url");
    body.client_challenge = crypto.createHash("sha256").update(secret).digest("hex");
    started = { email: emailOf(body), secret };
  }
  if ((apiPath === "/api/auth/verify-email" || apiPath === "/api/auth/complete-signup")
      && body && pending && pending.email === emailOf(body)) {
    body.device_secret = pending.secret;
  }

  const res = await request(method, apiPath, body, !NO_TOKEN.has(apiPath));

  if (started && res.status === 202) pending = started;
  if (TOKEN_PATHS.has(apiPath) && res.data && typeof res.data.token === "string") {
    auth = {
      token: res.data.token,
      portal: res.data.portal,
      persist: res.data.portal === "user" && apiPath === "/api/auth/login" && !!(body && body.remember === true),
    };
    delete res.data.token;                       // the page never receives the token
    if (auth.persist) saveSession(); else clearSavedSession();
    pending = null;
  }
  if (apiPath === "/api/auth/logout" || (res.status === 401 && auth && !NO_TOKEN.has(apiPath))) {
    auth = null;
    clearSavedSession();
  }
  return res;
});

ipcMain.handle("app:take-pending-page", () => {
  const p = pendingPage;
  pendingPage = null;
  return p;
});

ipcMain.handle("session:restore", async () => {
  if (!auth) {
    const saved = loadSavedSession();
    if (!saved) return null;
    auth = { token: saved.token, portal: saved.portal, persist: true };
  }
  const res = await request("GET", "/api/me", undefined, true);
  if (res.status === 200 && res.data && res.data.user) return { user: res.data.user, portal: res.data.portal };
  if (res.status === 401) clearSavedSession();   // expired or revoked; if the server was just unreachable, keep the file
  auth = null;
  return null;
});

// ---- window ----------------------------------------------------------------------------------------------------
function createWindow() {
  const win = new BrowserWindow({
    width: 1100, height: 760, minWidth: 900, minHeight: 640,
    title: "SafeBrowse", backgroundColor: "#f8fafc", autoHideMenuBar: true,
    webPreferences: {
      preload: path.join(__dirname, "preload.cjs"),
      contextIsolation: true, nodeIntegration: false, sandbox: true, webSecurity: true,
    },
  });
  win.webContents.setWindowOpenHandler(() => ({ action: "deny" }));
  win.webContents.on("will-navigate", (e, url) => { if (!(DEV && url.startsWith(DEV_URL))) e.preventDefault(); });
  if (DEV) win.loadURL(DEV_URL);
  else win.loadFile(path.join(__dirname, "..", "dist", "index.html"));
}

if (!app.requestSingleInstanceLock()) {
  app.quit();
} else {
  function showPage(page) {
    const [w] = BrowserWindow.getAllWindows();
    if (w) {
      if (w.isMinimized()) w.restore();
      w.focus();
      if (page) w.webContents.send("open-page", page);
    } else if (page) pendingPage = page;
  }
  app.on("second-instance", (_event, argv) => {
    const link = argv.find((a) => typeof a === "string" && a.startsWith(PROTOCOL + "://"));
    showPage(link ? pageFromProtocolUrl(link) : null);
  });
  app.on("open-url", (event, url) => {               // macOS
    event.preventDefault();
    showPage(pageFromProtocolUrl(url));
  });
  const firstLink = process.argv.find((a) => typeof a === "string" && a.startsWith(PROTOCOL + "://"));
  if (firstLink) pendingPage = pageFromProtocolUrl(firstLink);
  app.whenReady().then(() => {
    app.setAppUserModelId("com.safebrowse.desktop");
    try {
      if (process.defaultApp) {                        // started with `electron .` (development)
        if (process.argv.length >= 2) app.setAsDefaultProtocolClient(PROTOCOL, process.execPath, [path.resolve(process.argv[1])]);
      } else app.setAsDefaultProtocolClient(PROTOCOL);
    } catch { /* the link feature is optional */ }
    if (!DEV) Menu.setApplicationMenu(null);
    session.defaultSession.setPermissionRequestHandler((_wc, _perm, cb) => cb(false));
    if (DEV) {
      // The built app carries its strict policy in index.html; the dev server needs inline scripts and a websocket.
      const csp = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; " +
                  "img-src 'self' data:; font-src 'self' data:; connect-src 'self' ws://127.0.0.1:5173; object-src 'none'";
      session.defaultSession.webRequest.onHeadersReceived((details, cb) => {
        cb({ responseHeaders: { ...details.responseHeaders, "Content-Security-Policy": [csp] } });
      });
    }
    createWindow();
    app.on("activate", () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });
  });
  app.on("window-all-closed", () => { if (process.platform !== "darwin") app.quit(); });
}

module.exports = { pageFromProtocolUrl };
