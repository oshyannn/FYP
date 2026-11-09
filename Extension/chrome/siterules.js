// SafeBrowse: what the person chose for each website (loaded by background.js with importScripts).
//
//   ask      (default) a warning every time
//   once     "Just this visit": no warning for 2 minutes, then it asks again
//   hour     no warning for 1 hour
//   session  no warning until the browser is closed
//   allow    always allow, saved to the account (Supabase table url_lists) so it follows the person and can be undone
//   block    always block, saved the same way
//
// "once", "hour" and "session" live in this browser only. "allow" and "block" are read from the server (cached for a minute)
// and also kept in chrome.storage.local, so they still work after the service worker restarts or the server is offline.
// The warning page (blocked.js) and the popup talk to this file with "site-get" / "site-set" / "site-list" messages.
"use strict";

const RULES_TTL = 60 * 1000;
const ONCE_MS = 2 * 60 * 1000;
const HOUR_MS = 60 * 60 * 1000;
const SITE_MODES = ["ask", "once", "hour", "session", "allow", "block"];
let rulesCache = null;                 // { map: { "example.com": "allow" | "block" }, at }
let rulesLoading = null;

const bareHost = (h) => String(h || "").toLowerCase().replace(/^www\./, "");

async function siteApi(method, path, body) {
    const token = await getToken();
    if (!token) return { ok: false, status: 401, error: "Pair this extension with the desktop app first." };
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), 5000);
    try {
        const r = await fetch(API_BASE + path, { method, headers: authHeaders(token), body: body ? JSON.stringify(body) : undefined, signal: ctl.signal });
        if (r.status === 401) { await chrome.storage.local.remove("auth"); return { ok: false, status: 401, error: "Your session ended. Pair the extension again." }; }
        const data = await r.json().catch(() => null);
        if (!r.ok) return { ok: false, status: r.status, error: (data && data.error && data.error.message) || "Request failed." };
        return { ok: true, status: r.status, data };
    } catch {
        return { ok: false, status: 0, error: "Can't reach the SafeBrowse server. Make sure the backend is running." };
    } finally { clearTimeout(timer); }
}

function keepRules(map) {
    rulesCache = { map, at: Date.now() };
    try { chrome.storage.local.set({ siteRules: rulesCache }); } catch {}
}

async function refreshRules() {
    if (rulesLoading) return rulesLoading;
    rulesLoading = (async () => {
        const r = await siteApi("GET", "/api/site-rules");
        if (r.ok) {
            const map = {};
            for (const x of r.data.rules || []) map[bareHost(x.host)] = x.rule;
            keepRules(map);
        } else if (!rulesCache) {
            rulesCache = { map: {}, at: Date.now() };            // nothing known and the server is not answering: carry on without rules
        } else {
            rulesCache.at = Date.now() - RULES_TTL + 10000;      // keep the old rules, try again in 10 s
        }
        return rulesCache.map;
    })().finally(() => { rulesLoading = null; });
    return rulesLoading;
}

async function loadRules() {
    if (!rulesCache) { try { rulesCache = (await chrome.storage.local.get("siteRules")).siteRules || null; } catch {} }
    if (rulesCache && Date.now() - rulesCache.at < RULES_TTL) return rulesCache.map;
    if (rulesCache) { refreshRules().catch(() => {}); return rulesCache.map; }      // old copy now, a new one in a moment
    return refreshRules();                                                           // first time: wait (5 s at most)
}

// The saved rule that covers this host: the host itself or a parent domain (a rule for example.com covers a.example.com).
function ruleKey(map, host) {
    const parts = bareHost(host).split(".");
    for (let i = 0; i < parts.length - 1; i++) {
        const k = parts.slice(i).join(".");
        if (map[k]) return k;
    }
    return null;
}

async function siteDecision(url) {
    const host = new URL(url).hostname.toLowerCase();
    const map = await loadRules();
    const k = ruleKey(map, host);
    if (k) return map[k];                                       // "allow" | "block"
    if (await mapHas("tempAllow", host) || await mapHas("once", host)) return "allow";
    return null;
}

function userBlockedPage(url) {
    const q = new URLSearchParams({ url, score: "100", kind: "userblock", reasons: JSON.stringify(["You chose to always block this website."]) });
    return chrome.runtime.getURL("blocked.html") + "?" + q;
}

// Called for every page that is about to open. true = handled here (blocked, or allowed on purpose), skip the normal check.
async function siteGate(d) {
    let decision;
    try { decision = await siteDecision(d.url); } catch { return false; }
    if (decision === "block") { chrome.tabs.update(d.tabId, { url: userBlockedPage(d.url) }); return true; }
    if (decision === "allow") { analyze(d.url, { record: true }).catch(() => {}); return true; }     // still saved to the history, never blocked
    return false;
}

// Same for the page a redirect ended on.
async function siteGateRedirect(d) {
    let decision;
    try { decision = await siteDecision(d.url); } catch { return false; }
    if (decision === "block") { chrome.tabs.update(d.tabId, { url: userBlockedPage(d.url) }); return true; }
    return decision === "allow";
}

async function sessionAllow(host, on) {
    try {
        const s = await chrome.storage.session.get("allowed");
        const set = new Set(s.allowed || []);
        if (on) set.add(host); else set.delete(host);
        await chrome.storage.session.set({ allowed: [...set] });
    } catch {}
}
async function clearTemporary(host) {
    await mapDel("tempAllow", host);
    await mapDel("once", host);
    await sessionAllow(host, false);
}

async function siteState(host) {
    host = String(host || "").toLowerCase();
    const map = await loadRules();
    const k = ruleKey(map, host);
    const rule = k ? map[k] : null;
    let session = false;
    try { session = ((await chrome.storage.session.get("allowed")).allowed || []).includes(host); } catch {}
    let hour = null, once = false;
    try {
        const m = await chrome.storage.local.get(["tempAllow", "once"]);
        const h = (m.tempAllow || {})[host], o = (m.once || {})[host];
        hour = h && h > Date.now() ? h : null;
        once = !!(o && o > Date.now());
    } catch {}
    const mode = rule === "block" ? "block" : rule === "allow" ? "allow" : hour ? "hour" : session ? "session" : once ? "once" : "ask";
    return { host, rule, ruleHost: k, hour, session, once, mode };
}

async function setSite(host, mode) {
    host = String(host || "").toLowerCase();
    if (!host || !SITE_MODES.includes(mode)) return { ok: false, error: "Choose one of the options." };
    const map = await loadRules();
    if (mode === "allow" || mode === "block") {
        const r = await siteApi("PUT", "/api/site-rules", { host, rule: mode });
        if (!r.ok) return r;
        await clearTemporary(host);
        keepRules({ ...map, [bareHost(host)]: mode });
        return { ok: true, state: await siteState(host) };
    }
    const k = ruleKey(map, host);
    if (k) {                                                                  // a saved rule would override a temporary choice
        const r = await siteApi("DELETE", "/api/site-rules?host=" + encodeURIComponent(k));
        if (!r.ok && r.status !== 404) return r;
        const next = { ...map }; delete next[k]; keepRules(next);
    }
    await clearTemporary(host);
    if (mode === "once") await mapAdd("once", host, ONCE_MS);
    else if (mode === "hour") await mapAdd("tempAllow", host, HOUR_MS);
    else if (mode === "session") await sessionAllow(host, true);
    return { ok: true, state: await siteState(host) };
}

chrome.runtime.onMessage.addListener((msg, sender, send) => {
    if (sender.id !== chrome.runtime.id || !msg || typeof msg.type !== "string" || !msg.type.startsWith("site-")) return;
    if (!String(sender.url || "").startsWith(chrome.runtime.getURL(""))) return;      // our own pages only, never a content script
    (async () => {
        try {
            if (msg.type === "site-get") send({ ok: true, state: await siteState(msg.host) });
            else if (msg.type === "site-set") send(await setSite(msg.host, msg.mode));
            else if (msg.type === "site-list") {
                const r = await siteApi("GET", "/api/site-rules");
                if (!r.ok) return send(r);
                const map = {};
                for (const x of r.data.rules || []) map[bareHost(x.host)] = x.rule;
                keepRules(map);
                send({ ok: true, rules: r.data.rules || [] });
            } else send({ ok: false, error: "Unknown request." });
        } catch { send({ ok: false, error: "Something went wrong." }); }
    })();
    return true;
});
