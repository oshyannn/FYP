console.log("Background running...");

// A missing manifest permission leaves that chrome.* API undefined; one such call at load time would stop the whole
// script. Say clearly which permission is missing, and keep the parts that can still work.
const MISSING = ["tabs", "webNavigation", "notifications", "storage", "downloads"].filter((p) => !chrome[p]);
if (MISSING.length) console.error("manifest.json is missing permissions: " + MISSING.join(", ") + " (add them to \"permissions\", then reload the extension)");

const API_BASE = "http://127.0.0.1:5000";   // keep in sync with Extension/ui/src/config.ts
const API = API_BASE + "/analyze";
const ICON = chrome.runtime.getURL("icons/icon128.png");
const QUICK_MS = 700;                 // answered within this -> decide at once (whitelist/blacklist hits are instant)
const DEEP_MS = 15000;                // slower check: the user waits on a "checking" page, then fail-open
const CACHE_MS = 5 * 60 * 1000;
const cache = new Map();              // url -> { t, data }
const pending = new Map();            // url -> Promise<data> (one request per URL, shared by every caller)
const notified = new Set();

// ---------------------------------------------------------------- helpers
function shouldScan(rawUrl) {
    let u;
    try { u = new URL(rawUrl); } catch { return false; }
    if (u.protocol !== "http:" && u.protocol !== "https:") return false;
    const host = u.hostname;
    if (host === "localhost" || host === "127.0.0.1" || host === "::1") return false;
    if (/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(host)) return false;
    if (!host.includes(".")) return false;
    if (host === "claude.ai" || host.endsWith(".claude.ai")) return false;
    return true;
}

// Notifications can fail (missing icon file, a platform that rejects buttons). Never let that hide the warning:
// retry with a built-in icon and no buttons, and log the reason.
const FALLBACK_ICON = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==";
function notify(id, opts) {
    return new Promise((resolve) => {
        const done = (ok) => resolve(ok);
        try {
            chrome.notifications.create(id || "", opts, () => {
                if (!chrome.runtime.lastError) return done(true);
                console.error("notification failed, retrying simpler:", chrome.runtime.lastError.message);
                const { buttons, requireInteraction, ...plain } = opts;
                chrome.notifications.create(id || "", { ...plain, iconUrl: FALLBACK_ICON }, () => {
                    if (chrome.runtime.lastError) console.error("notification failed again:", chrome.runtime.lastError.message);
                    done(!chrome.runtime.lastError);
                });
            });
        } catch (err) {
            console.error("notification error:", err);
            done(false);
        }
    });
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---------------------------------------------------------------- account (paired with the desktop app), settings, history
// The popup stores {auth, settings, history} in chrome.storage.local. The token comes from the pairing code, never from a password.
const DEFAULT_SETTINGS = { realtime: true, autoscan: true, blocking: true, notifications: true };
async function getSettings() {
    try { return { ...DEFAULT_SETTINGS, ...((await chrome.storage.local.get("settings")).settings || {}) }; }
    catch { return { ...DEFAULT_SETTINGS }; }
}
async function getToken() {
    try { return ((await chrome.storage.local.get("auth")).auth || {}).token || null; }
    catch { return null; }
}
async function refreshBadge() {
    const paired = !!(await getToken());
    chrome.action?.setBadgeText({ text: paired ? "" : "!" });
    chrome.action?.setBadgeBackgroundColor({ color: "#dc2626" });
    chrome.action?.setTitle({ title: paired ? "SafeBrowse" : "SafeBrowse: pair with the desktop app to start protection" });
}
chrome.storage.onChanged.addListener((changes, area) => { if (area === "local" && changes.auth) refreshBadge(); });
chrome.runtime.onStartup?.addListener(refreshBadge);
chrome.runtime.onInstalled.addListener(refreshBadge);
refreshBadge();

// Scan history shown in the popup (newest first, max 200). TODO(supabase): also send each record to the backend.
const HISTORY_MAX = 200;
let historyChain = Promise.resolve();            // writes are queued so two quick scans cannot overwrite each other
function toStatus(d) {
    if (!d || !d.has_data) return "unknown";
    return d.status === "Safe" ? "safe" : d.status === "Suspicious" ? "suspicious" : "malicious";   // "Restricted" (adult) counts as blocked
}
function toVerdict(url, d) {
    return {
        url, status: toStatus(d), score: Number(d && d.risk_score) || 0,
        reasons: Array.isArray(d && d.reasons) ? d.reasons.map(String).slice(0, 12) : [],
        source: String((d && d.source) || ""), adult: !!d && d.status === "Restricted", ts: Date.now(),
    };
}
function recordHistory(url, d, kind) {
    historyChain = historyChain.then(async () => {
        try {
            const list = (await chrome.storage.local.get("history")).history || [];
            const v = toVerdict(url, d);
            if (kind !== "manual" && list.some((h) => h.url === url && v.ts - h.ts < 60000)) return;   // same page opened again within a minute
            list.unshift({ ...v, id: v.ts + "-" + Math.random().toString(36).slice(2, 8), kind });
            await chrome.storage.local.set({ history: list.slice(0, HISTORY_MAX) });
        } catch (err) { console.error("could not save history:", err); }
    });
}

function reasonText(data) {
    const r = Array.isArray(data.reasons) ? data.reasons.slice(0, 2).join(" ") : "";
    return r.length > 180 ? r.slice(0, 177) + "..." : r;
}

// opts.record: also store the verdict in the popup history (page loads and manual scans, not background look-ups of referrers)
// opts.force: ignore the 5-minute cache (manual "Scan again")
function analyze(url, opts = {}) {
    const done = (p) => (opts.record ? p.then((d) => { recordHistory(url, d, opts.kind || "auto"); return d; }) : p);
    const hit = cache.get(url);
    if (!opts.force && hit && Date.now() - hit.t < CACHE_MS) return done(Promise.resolve(hit.data));
    if (!opts.force && pending.has(url)) return done(pending.get(url));
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), DEEP_MS);
    const p = getToken()
        .then((token) => fetch(API, {
            method: "POST",
            headers: { "Content-Type": "application/json", ...(token ? { Authorization: "Bearer " + token } : {}) },
            body: JSON.stringify({ url }),
            signal: ctl.signal,
        }))
        .then(async (r) => {
            if (r.status === 401) {                                  // token revoked/expired (or never paired): ask for a new pairing code
                await chrome.storage.local.remove("auth");
                const e = new Error("Not paired with the desktop app."); e.code = "unauthenticated"; e.status = 401; throw e;
            }
            const data = await r.json();
            if (!r.ok) { const e = new Error((data && (data.message || (data.error && data.error.message))) || "Analysis failed."); e.status = r.status; throw e; }
            return data;
        })
        .then((data) => {
            if (cache.size > 500) cache.clear();
            cache.set(url, { t: Date.now(), data });
            return data;
        })
        .finally(() => { clearTimeout(timer); if (pending.get(url) === p) pending.delete(url); });
    pending.set(url, p);
    return done(p);
}

async function isAllowed(url) {
    try {
        const host = new URL(url).hostname;
        const s = await chrome.storage.session.get("allowed");
        return (s.allowed || []).includes(host);
    } catch { return false; }
}

// Small host -> expiry maps kept in chrome.storage.local ("good" = remembered clean sites, "dlAllow" = sites whose downloads you accepted)
async function mapHas(key, host) {
    try {
        const m = (await chrome.storage.local.get(key))[key] || {};
        return !!m[host] && m[host] > Date.now();
    } catch { return false; }
}
async function mapAdd(key, host, ms) {
    try { await mapAddUnsafe(key, host, ms); } catch {}
}
async function mapAddUnsafe(key, host, ms) {
    const m = (await chrome.storage.local.get(key))[key] || {};
    const now = Date.now();
    for (const k of Object.keys(m)) if (m[k] <= now) delete m[k];
    m[host] = now + ms;
    await chrome.storage.local.set({ [key]: m });
}
async function mapDel(key, host) {
    try {
        const m = (await chrome.storage.local.get(key))[key] || {};
        delete m[host];
        await chrome.storage.local.set({ [key]: m });
    } catch {}
}
const GOOD_MS = 3 * 24 * 3600 * 1000;       // a clean site skips the waiting page for 3 days, but is still checked every time
const DL_ALLOW_MS = 30 * 24 * 3600 * 1000;

// Remember a site that was checked and found clean (not flagged), so the next visit needs no waiting page.
function rememberIfClean(url, data) {
    if (!data) return;
    const clean = !data.has_data || (data.status === "Safe" && !["whitelist", "trusted-suffix"].includes(data.source));
    if (clean) { try { mapAdd("good", new URL(url).hostname, GOOD_MS); } catch {} }
}

const isBlockable = (d) => !!d && d.has_data && (d.status === "Malicious" || d.status === "Restricted");

function blockedPage(url, data) {
    const q = new URLSearchParams({
        url,
        score: String(data.risk_score),
        kind: data.status === "Restricted" ? "adult" : "malicious",
        reasons: JSON.stringify((data.reasons || []).slice(0, 4)),
    });
    return chrome.runtime.getURL("blocked.html") + "?" + q;
}

async function cautionNotice(url, data) {
    if (!(await getSettings()).notifications) return;
    if (notified.has(url)) return;
    notified.add(url);
    if (notified.size > 200) notified.clear();
    notify("", {
        type: "basic", iconUrl: ICON, title: "⚠ Caution",
        message: "This site shows signs of risk. Proceed carefully.\n" + reasonText(data),
    });
}

// Act on a verdict for a page that is already loading: block it, warn about it, or leave it alone.
async function act(tabId, url, data) {
    if (!data || !data.has_data) return;           // Unknown: not flagged, not confirmed safe
    if (isBlockable(data)) {
        if ((await getSettings()).blocking) chrome.tabs.update(tabId, { url: blockedPage(url, data) });
        else notifyBlockingOff(url, data);           // "Website Blocking" is off: warn, do not block
    } else if (data.status === "Suspicious") cautionNotice(url, data);
}
async function notifyBlockingOff(url, data) {
    if (!(await getSettings()).notifications || notified.has("off:" + url)) return;
    notified.add("off:" + url);
    notify("", { type: "basic", iconUrl: ICON, title: "⚠ Dangerous website", message: "Blocking is OFF, so this page was not blocked.\n" + reasonText(data) });
}

// ---------------------------------------------------------------- 1. check every navigation before the page shows
chrome.webNavigation?.onBeforeNavigate.addListener(async (d) => {
    if (!(await getSettings()).realtime) return;     // "Real-Time URL Detection" is off
    await noteNavigation(d);                        // remember navigations a person started (localhost included)
    if (d.frameId !== 0 || !shouldScan(d.url)) return;
    if (await isAllowed(d.url)) return;

    const p = analyze(d.url, { record: true });
    p.catch(() => {});                              // handled below; avoids an unhandled-rejection warning
    const host = new URL(d.url).hostname;
    if (await mapHas("good", host)) {
        // Known clean recently: no waiting page. The check still runs; if it turns bad the page is blocked.
        p.then((data) => {
            if (isBlockable(data) || (data && data.status === "Suspicious")) mapDel("good", host);
            act(d.tabId, d.url, data);
        }).catch(() => {});
        return;
    }
    let data;
    try {
        data = await Promise.race([p, sleep(QUICK_MS).then(() => null)]);
    } catch (err) {
        console.error("API error (not blocked, backend unreachable?):", err);
        return;                                     // fail open: a dead backend must not break browsing
    }
    if (data === null) {                            // not instant: hold the user on a waiting page
        chrome.tabs.update(d.tabId, { url: chrome.runtime.getURL("checking.html") + "?url=" + encodeURIComponent(d.url) });
        return;
    }
    rememberIfClean(d.url, data);
    act(d.tabId, d.url, data);
});

// The waiting page asks for the verdict (the same in-flight request, not a second one).
chrome.runtime.onMessage.addListener((msg, sender, send) => {
    if (sender.id !== chrome.runtime.id || !msg || msg.type !== "verify" || !shouldScan(msg.url)) return;
    (async () => {
        try {
            const data = await analyze(msg.url, { record: true });
            if (data && data.has_data && data.status === "Suspicious") cautionNotice(msg.url, data);
            rememberIfClean(msg.url, data);
            if (isBlockable(data) && !(await getSettings()).blocking) notifyBlockingOff(msg.url, data);
            send(isBlockable(data) && (await getSettings()).blocking ? { action: "block", blockedUrl: blockedPage(msg.url, data) } : { action: "allow" });
        } catch (err) {
            console.error("API error (page allowed, check failed):", err);
            send({ action: "allow", failed: true });
        }
    })();
    return true;                                    // keep the channel open for the async reply
});

// The popup asks for a verdict (current page or the "Scan URL" tab). Only our own popup page may ask.
chrome.runtime.onMessage.addListener((msg, sender, send) => {
    if (sender.id !== chrome.runtime.id || !msg || msg.type !== "scan") return;
    if (!String(sender.url || "").startsWith(chrome.runtime.getURL("popup/"))) return;
    if (typeof msg.url !== "string" || !/^https?:\/\//i.test(msg.url)) { send({ ok: false, error: { code: "bad_url", message: "Enter a valid http(s) address." } }); return; }
    analyze(msg.url, { force: !!msg.force, record: !!msg.record, kind: msg.kind === "manual" ? "manual" : "auto" })
        .then((data) => send({ ok: true, verdict: toVerdict(msg.url, data) }))
        .catch((err) => send({ ok: false, error: { code: err.code || (err.name === "AbortError" ? "timeout" : "offline"), status: err.status || 0,
            message: err.status ? err.message : err.name === "AbortError" ? "The check took too long. Try again." : "Can't reach the SafeBrowse server. Is the backend running?" } }));
    return true;
});

// ---------------------------------------------------------------- 2. redirects: check where you ended up
// A server redirect only fires onBeforeNavigate for the FIRST address; onCommitted reports the final one.
chrome.webNavigation?.onCommitted.addListener(async (d) => {
    if (d.frameId !== 0 || !shouldScan(d.url)) return;
    const q = d.transitionQualifiers || [];
    if (!q.includes("server_redirect") && !q.includes("client_redirect")) return;
    if (!(await getSettings()).realtime) return;
    if (await isAllowed(d.url)) return;
    try {
        act(d.tabId, d.url, await analyze(d.url, { record: true }));
    } catch (err) {
        console.error("API error while checking redirect target:", err);
    }
});

// ---------------------------------------------------------------- 3. downloads
const RISKY_NAME = /\.(exe|msi|scr|bat|cmd|pif|apk|jar|js|jse|vbs|vbe|ps1|hta|lnk|reg|dll|sh|dmg|pkg|iso|img|docm|xlsm|pptm)$/i;
const RISKY_MIME = /(x-msdownload|x-msdos-program|x-dosexec|vnd\.android\.package-archive|x-sh|x-bat|java-archive)/i;
const allowedDownloads = new Set();
const pendingDownloads = {};                // memory copy, used if chrome.storage.session is unavailable

function fileName(item) {
    const named = (item.filename || "").split(/[\\/]/).pop();
    if (named) return named;
    try { return decodeURIComponent(new URL(item.finalUrl || item.url).pathname.split("/").pop()); } catch { return ""; }
}

async function verdictOf(url) {
    if (!url || !shouldScan(url)) return null;
    try { return await analyze(url); } catch { return null; }
}

// ---- real user gestures, reported by content.js (only "a person really clicked/pressed Enter", never page content)
const GESTURE_MS = 4000;
let lastGesture = null;                                  // { t, host }
chrome.runtime.onMessage.addListener((msg, sender) => {
    if (sender.id !== chrome.runtime.id || !msg || msg.type !== "gesture" || !sender.tab) return;
    let host = "";
    try { host = new URL(sender.url || sender.tab.url).hostname; } catch {}
    lastGesture = { t: Date.now(), host };
    try { chrome.storage.session.set({ gesture: lastGesture }); } catch {}   // the worker may be asleep next time
});
// A click on a real link starts a NAVIGATION at once; the file may only arrive many seconds later (slow server, redirects).
// So a navigation that began right after a real click is remembered, and a download for that same URL is still "yours".
const SLOW_MS = 30000;
let userNav = null;                                      // { t, url, host }
async function noteNavigation(d) {
    if (d.frameId !== 0) return;
    const g = await recentGesture();
    if (g) {
        userNav = { t: Date.now(), url: d.url, host: g.host };
        try { chrome.storage.session.set({ userNav }); } catch {}
    }
}
async function recentUserNav() {
    let n = userNav;
    if (!n) { try { n = (await chrome.storage.session.get("userNav")).userNav || null; } catch {} }
    return n && Date.now() - n.t <= SLOW_MS ? n : null;
}

async function recentGesture() {
    let g = lastGesture;
    if (!g) { try { g = (await chrome.storage.session.get("gesture")).gesture || null; } catch {} }
    return g && Date.now() - g.t <= GESTURE_MS ? g : null;
}

const TWO_LEVEL = new Set(["com", "co", "org", "net", "gov", "edu", "ac"]);
function site(host) {                                    // registered domain, good enough for .com / .co.uk / .com.my
    const p = (host || "").toLowerCase().replace(/^www\./, "").split(".");
    if (p.length <= 2) return p.join(".");
    return p.slice(TWO_LEVEL.has(p[p.length - 2]) && p[p.length - 1].length === 2 ? -3 : -2).join(".");
}
const sameSite = (a, b) => !!a && !!b && site(a) === site(b);
const hostOf = (u) => { try { return new URL(u).hostname; } catch { return ""; } };

// A risky download is held at the "choosing the file name" step (onDeterminingFilename): until we answer, Chrome does not give it
// a name, does not save it as a finished file, and it cannot be opened. id -> suggest() callback that lets it continue.
const holding = new Map();
const asking = new Map();   // id -> { url, finished }: downloads whose question is still open
function release(id) {
    const go = holding.get(id);
    console.log("release download", id, go ? "(suggest called)" : "(resume fallback)");
    if (go) { holding.delete(id); try { go(); } catch {} }
    else chrome.downloads.resume(id).catch(() => {});      // fallback for downloads that were only paused
}

// Stop a download for good. A tiny file may already be finished by the time we decide, so cancel is not enough: delete it too.
async function discard(id) {
    holding.delete(id);
    try { await chrome.downloads.cancel(id); } catch {}
    try {
        const [it] = await chrome.downloads.search({ id });
        if (it && it.state === "complete" && it.exists !== false) await chrome.downloads.removeFile(id);
        if (it && it.state === "complete") await chrome.downloads.erase({ id });
    } catch (err) { console.error("could not remove the finished file:", err); }
}

// Ask the person in a small dialog while the download is held. Returns false if the dialog could not be opened.
async function askUser(item, why, hosts, info) {
    try {
        const q = new URLSearchParams({
            id: String(item.id), file: fileName(item), why, from: info.fileHost || "", page: info.pageHost || "",
            trusted: info.trusted ? "1" : "0", hosts: hosts.slice(0, 4).join(","),
        });
        console.log("opening download dialog for", fileName(item));
        asking.set(item.id, { url: item.url, finished: false });
        await chrome.windows.create({ url: chrome.runtime.getURL("prompt.html") + "?" + q, type: "popup", width: 500, height: 360, focused: true });
        return true;
    } catch (err) {
        console.error("could not open the download dialog, blocking instead:", err);
        return false;
    }
}

chrome.runtime.onMessage.addListener((msg, sender) => {      // the dialog reports the person's choice
    if (sender.id !== chrome.runtime.id || !msg || msg.type !== "prompt-decision") return;
    if (!String(sender.url || "").startsWith(chrome.runtime.getURL("prompt.html"))) return;
    const id = Number(msg.id);
    if (!Number.isInteger(id)) return;
    const ask = asking.get(id);
    asking.delete(id);
    if (msg.choice === "allow" || msg.choice === "always") {
        if (msg.choice === "always") for (const h of (Array.isArray(msg.hosts) ? msg.hosts : []).slice(0, 4)) if (typeof h === "string" && h) mapAdd("dlAllow", h, DL_ALLOW_MS);
        if (ask && ask.finished) {                   // Chrome finished it before you answered and we deleted it: fetch it again now
            if (/^https?:/i.test(ask.url)) { allowedDownloads.add(ask.url); chrome.downloads.download({ url: ask.url }); }
        } else release(id);
    } else {
        discard(id);
    }
});

async function guard(item, held) {
  try {
    if (!(await getSettings()).realtime) return;      // protection switched off in the popup
    const src = item.finalUrl || item.url;
    if (allowedDownloads.has(item.url)) { allowedDownloads.delete(item.url); return; }
    const web = /^https?:/i.test(src || "");
    const generated = /^(blob|data):/i.test(src || "");   // a script built the file inside the page: a favourite malware trick
    if (!web && !generated) return;

    const risky = RISKY_NAME.test(fileName(item)) || RISKY_MIME.test(item.mime || "");
    if (generated && !risky) return;                // harmless types made by a page (exported csv, saved image...) are left alone
    if (risky && !held) chrome.downloads.pause(item.id).catch(() => {});   // older fallback: pause (a tiny file may already be finished)

    const fileHost = web ? hostOf(src) : hostOf((src || "").replace(/^blob:/i, ""));
    let gesture = await recentGesture();           // did a person click / press Enter just before?
    if (!gesture) {                                // ...or did a click start a navigation to exactly this file (slow network)?
        const n = await recentUserNav();
        if (n && (n.url === item.url || n.url === item.finalUrl)) gesture = { t: n.t, host: n.host };
    }
    const hosts = [fileHost, hostOf(item.referrer)].filter(Boolean);
    const [fromSrc, fromPage, fromClick] = await Promise.all([
        verdictOf(web ? src : null), verdictOf(item.referrer), gesture && gesture.host ? verdictOf("https://" + gesture.host + "/") : null]);
    const checked = [fromSrc, fromPage, fromClick];
    const flagged = checked.some((d) => d && d.has_data && (d.status === "Malicious" || d.status === "Suspicious"));
    const confirmedBad = checked.some((d) => d && d.has_data && d.status === "Malicious");
    const trusted = checked.some((d) => d && d.status === "Safe" && ["whitelist", "trusted-suffix"].includes(d.source));
    let allowedSite = false;                         // sites whose downloads you accepted before ("Always allow this site")
    if (!confirmedBad) for (const h of hosts) if (await mapHas("dlAllow", h)) allowedSite = true;
    const sameSiteClick = !!gesture && sameSite(fileHost, gesture.host);

    let why = null;                                  // null = allow
    let soft = false;                                // soft = ask the person (dialog); hard = flagged/malicious source, blocked
    if (confirmedBad) why = "The source is confirmed malicious.";
    else if (!risky) { if (flagged && !allowedSite && !trusted) why = "The source site is flagged as risky."; }
    else if (allowedSite) why = null;
    else if (flagged) why = "The source site is flagged as risky.";
    else if (!gesture) { why = "A program/script file started by itself (no click or key press just before)."; soft = true; }
    else if (generated) { if (!(trusted && sameSiteClick)) { why = "A page script created a program/script file inside your browser."; soft = true; } }
    else if (!sameSiteClick) { why = `You clicked on ${gesture.host || "a page"}, but the file comes from a different website (${fileHost}).`; soft = true; }
    console.log("Download decision:", { file: fileName(item), fileHost, clickedOn: gesture && gesture.host, risky, flagged, trusted, allowedSite, blocked: !!why, ask: soft, gesture: !!gesture, why });

    if (!why) {
        if (risky) chrome.downloads.resume(item.id).catch(() => {});
        return;
    }
    if (soft && await askUser(item, why, hosts, { trusted, fileHost, pageHost: gesture && gesture.host })) return "wait";   // the answer arrives as a message
    discard(item.id);
    if (generated) {                                 // cannot be fetched again, so no "download anyway" button
        await notify("dlg:" + item.id, { type: "basic", iconUrl: ICON, title: "⚠ Download blocked", message: fileName(item) + "\n" + why });
        return;
    }
    const nid = "dl:" + item.id;
    pendingDownloads[nid] = { url: item.url, hosts };
    try {
        const s = await chrome.storage.session.get("dl");
        await chrome.storage.session.set({ dl: { ...(s.dl || {}), [nid]: { url: item.url, hosts } } });
    } catch (err) {
        console.error("could not save download info (using memory only):", err);
    }
    console.log("Download blocked:", fileName(item), "from", src);
    await notify(nid, {
        type: "basic", iconUrl: ICON, title: "⚠ Download blocked",
        message: fileName(item) + "\n" + why,
        buttons: [{ title: "Download anyway" }, { title: "Always allow this site" }],
        requireInteraction: true,
    });
  } catch (err) {
    console.error("download guard failed:", err);
  }
}

// Safety net: if a download whose question is still open finishes anyway, delete the file at once.
chrome.downloads?.onChanged?.addListener(async (delta) => {
    const a = asking.get(delta.id);
    if (!a) return;
    console.log("download state change while question is open:", delta.id, JSON.stringify(delta));
    if (delta.state && delta.state.current === "complete") {
        a.finished = true;
        try { await chrome.downloads.removeFile(delta.id); await chrome.downloads.erase({ id: delta.id }); console.log("removed the file that finished before you answered"); }
        catch (err) { console.error("could not remove it:", err); }
    }
});

if (chrome.downloads?.onDeterminingFilename) {
    chrome.downloads.onDeterminingFilename.addListener((item, suggest) => {
        const src = item.finalUrl || item.url || "";
        const risky = RISKY_NAME.test(fileName(item)) || RISKY_MIME.test(item.mime || "");
        if (!risky || !/^(https?|blob|data):/i.test(src)) {          // harmless types are not delayed; flagged sources are still checked in the background
            guard(item, false);
            return;
        }
        holding.set(item.id, () => suggest());                         // keep the file unnamed and unsaved until we have an answer
        const timer = setTimeout(() => { if (holding.has(item.id)) discard(item.id); }, 90000);   // safety net: never hold forever
        guard(item, true).catch(() => {}).then((r) => {
            if (r === "wait") return;                                   // the dialog is open; its answer calls release() or discard()
            clearTimeout(timer);
            release(item.id);                                           // allowed (or the check failed): let it continue. Blocked ones were already discarded
        });
        return true;                                                    // answer asynchronously
    });
} else {
    chrome.downloads?.onCreated.addListener((item) => { guard(item, false); });
}

chrome.notifications?.onButtonClicked.addListener(async (nid, idx) => {
    if (!nid.startsWith("dl:") || (idx !== 0 && idx !== 1)) return;
    let entry = pendingDownloads[nid];
    try { entry = ((await chrome.storage.session.get("dl")).dl || {})[nid] || entry; } catch {}
    if (entry && /^https?:/i.test(entry.url)) {
        if (idx === 1) for (const h of entry.hosts || []) await mapAdd("dlAllow", h, DL_ALLOW_MS);
        allowedDownloads.add(entry.url);
        chrome.downloads.download({ url: entry.url });
    }
    chrome.notifications.clear(nid);
});
