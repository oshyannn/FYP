// SafeBrowse Shields: Brave-style blocking of ads, trackers and pop-ups with declarativeNetRequest (loaded by background.js).
//
//   Static rulesets   rules/ads.json, rules/trackers.json   built from EasyList / EasyPrivacy by tools/build_dnr.py (domains only)
//   Dynamic rules     rebuilt here: "Shields off" for one website (allowAllRequests), plus the extra block / allow domains an
//                     administrator keeps in Supabase (GET /api/adblock/lists, refreshed about every 6 hours)
//   Pop-ups           a new tab opened by a page whose address is an ad domain is closed
//
// The person's choices live in chrome.storage.local "shields": { ads, trackers, popups, off: ["example.com", ...] }.
// Shields never touch the safety check: a malicious website is still stopped by the warning page, Shields on or off.
"use strict";

const SHIELD_DEFAULT = { ads: true, trackers: true, popups: true, off: [] };
const ADMIN_LISTS_TTL = 6 * 60 * 60 * 1000;
const ID_SITE = 1, ID_ADMIN_BLOCK = 20000, ID_ADMIN_ALLOW = 30000;       // dynamic rule id ranges
const MAX_ADMIN_DOMAINS = 5000;
let shieldsCache = null;
let adSet = null;                                                      // every blocked domain, for the pop-up check

async function getShields() {
    if (shieldsCache) return shieldsCache;
    try { shieldsCache = { ...SHIELD_DEFAULT, ...((await chrome.storage.local.get("shields")).shields || {}) }; }
    catch { shieldsCache = { ...SHIELD_DEFAULT }; }
    if (!Array.isArray(shieldsCache.off)) shieldsCache.off = [];
    return shieldsCache;
}
async function saveShields(s) {
    shieldsCache = s;
    try { await chrome.storage.local.set({ shields: s }); } catch { /* the next change saves it again */ }
}
const cleanHost = (h) => String(h || "").toLowerCase().replace(/^www\./, "").replace(/\.$/, "");
const validDomain = (d) => /^(?:[a-z0-9-]{1,63}\.)+[a-z]{2,63}$/.test(d);

async function adminLists() {
    try { return (await chrome.storage.local.get("adblockLists")).adblockLists || { block: [], allow: [], at: 0 }; }
    catch { return { block: [], allow: [], at: 0 }; }
}

// Turns the person's settings (and the administrator's lists) into enabled rulesets + dynamic rules. Safe to call at any time.
async function applyShields() {
    const dnr = chrome.declarativeNetRequest;
    if (!dnr) { console.error("manifest.json is missing the declarativeNetRequest permission"); return; }
    const s = await getShields();
    try {
        await dnr.updateEnabledRulesets({
            enableRulesetIds: [s.ads && "ads", s.trackers && "trackers"].filter(Boolean),
            disableRulesetIds: [!s.ads && "ads", !s.trackers && "trackers"].filter(Boolean),
        });
        const lists = await adminLists();
        const add = [];
        s.off.forEach((h, i) => add.push({                                         // Shields off for this website: nothing on its pages is blocked
            id: ID_SITE + i, priority: 4, action: { type: "allowAllRequests" },
            condition: { requestDomains: [h], resourceTypes: ["main_frame", "sub_frame"] } }));
        const block = (lists.block || []).filter(validDomain).slice(0, MAX_ADMIN_DOMAINS);
        const allow = (lists.allow || []).filter(validDomain).slice(0, MAX_ADMIN_DOMAINS);
        if (block.length && (s.ads || s.trackers)) add.push({ id: ID_ADMIN_BLOCK, priority: 1, action: { type: "block" },
            condition: { requestDomains: block, resourceTypes: ["sub_frame", "script", "image", "stylesheet", "object", "xmlhttprequest", "ping", "media", "font", "websocket", "other"] } });
        if (allow.length) add.push({ id: ID_ADMIN_ALLOW, priority: 2, action: { type: "allow" },     // beats the blocking rules (priority 1)
            condition: { requestDomains: allow } });
        const old = (await dnr.getDynamicRules()).map((r) => r.id);
        await dnr.updateDynamicRules({ removeRuleIds: old, addRules: add });
    } catch (e) { console.error("Shields: could not update the rules:", e && e.message); }
}

async function syncAdminLists(force) {
    const have = await adminLists();
    if (!force && Date.now() - (have.at || 0) < ADMIN_LISTS_TTL) return;
    if (typeof siteApi !== "function") return;
    const r = await siteApi("GET", "/api/adblock/lists");
    if (!r.ok) {
        if (r.status !== 401) await chrome.storage.local.set({ adblockLists: { ...have, at: Date.now() - ADMIN_LISTS_TTL + 10 * 60 * 1000 } });   // retry in 10 minutes
        return;
    }
    const clean = (a) => (Array.isArray(a) ? a.map(cleanHost).filter(validDomain) : []);
    await chrome.storage.local.set({ adblockLists: { block: clean(r.data.block), allow: clean(r.data.allow), at: Date.now() } });
    adSet = null;                                               // the pop-up check re-reads the administrator's domains
    await applyShields();
}

// ---------------------------------------------------------------- pop-ups
async function loadAdSet() {
    if (adSet) return adSet;
    const set = new Set();
    for (const name of ["ads", "trackers"]) {
        try {
            const rules = await (await fetch(chrome.runtime.getURL("rules/" + name + ".json"))).json();
            for (const r of rules) for (const d of (r.condition && r.condition.requestDomains) || []) set.add(d);
        } catch { /* a missing file only means fewer pop-ups are recognised */ }
    }
    const lists = await adminLists();
    for (const d of lists.block || []) set.add(d);
    adSet = set;
    return set;
}
async function isAdUrl(rawUrl) {
    let host;
    try { host = new URL(rawUrl).hostname.toLowerCase(); } catch { return false; }
    const lists = await adminLists();
    const set = await loadAdSet();
    const parts = host.split(".");
    for (let i = 0; i < parts.length - 1; i++) {
        const cand = parts.slice(i).join(".");
        if ((lists.allow || []).includes(cand)) return false;
        if (set.has(cand)) return true;
    }
    return false;
}

const popupTabs = new Map();                                       // tabId -> { opener, at }: tabs a page opened a moment ago
async function openerHost(tabId) {
    try { return cleanHost(new URL((await chrome.tabs.get(tabId)).url).hostname); } catch { return ""; }
}
async function closePopupIfAd(tabId, openerId, url) {
    const s = await getShields();
    if (!s.popups || !(await isAdUrl(url))) return false;
    if (openerId != null && s.off.includes(await openerHost(openerId))) return false;      // Shields are off on the page that opened it
    try { await chrome.tabs.remove(tabId); } catch { return false; }
    popupTabs.delete(tabId);
    try {
        const st = (await chrome.storage.local.get("shieldsStats")).shieldsStats || { popups: 0 };
        await chrome.storage.local.set({ shieldsStats: { popups: (st.popups || 0) + 1 } });
    } catch { /* the counter is only a courtesy */ }
    return true;
}
chrome.tabs?.onCreated.addListener((tab) => {
    if (tab.openerTabId == null) return;
    const now = Date.now();
    for (const [id, p] of popupTabs) if (now - p.at > 10000) popupTabs.delete(id);
    popupTabs.set(tab.id, { opener: tab.openerTabId, at: now });
    if (tab.pendingUrl || tab.url) closePopupIfAd(tab.id, tab.openerTabId, tab.pendingUrl || tab.url);
});
chrome.tabs?.onRemoved.addListener((id) => popupTabs.delete(id));
chrome.webNavigation?.onCreatedNavigationTarget.addListener((d) => { closePopupIfAd(d.tabId, d.sourceTabId, d.url); });
function popupNavigation(d) {                                       // a fresh pop-up that is sent on to an ad domain (redirect chain)
    if (d.frameId !== 0) return;
    const p = popupTabs.get(d.tabId);
    if (p && Date.now() - p.at < 10000) closePopupIfAd(d.tabId, p.opener, d.url);
}
chrome.webNavigation?.onBeforeNavigate.addListener(popupNavigation);
chrome.webNavigation?.onCommitted.addListener(popupNavigation);

// ---------------------------------------------------------------- state for the popup
async function blockedOnTab(tabId) {
    try {
        if (tabId == null || !chrome.declarativeNetRequest.getMatchedRules) return null;
        const r = await chrome.declarativeNetRequest.getMatchedRules({ tabId });
        return (r.rulesMatchedInfo || []).filter((m) => m.rule && (m.rule.rulesetId === "ads" || m.rule.rulesetId === "trackers" ||
            (m.rule.rulesetId === "_dynamic" && m.rule.ruleId === ID_ADMIN_BLOCK))).length;
    } catch { return null; }
}
async function shieldState(host, tabId) {
    const s = await getShields();
    const h = cleanHost(host);
    const stats = (await chrome.storage.local.get("shieldsStats").catch(() => ({}))).shieldsStats || { popups: 0 };
    return { ads: s.ads, trackers: s.trackers, popups: s.popups, host: h, siteOff: !!h && s.off.includes(h),
             blocked: await blockedOnTab(tabId), popupsBlocked: stats.popups || 0 };
}

chrome.runtime.onMessage.addListener((msg, sender, send) => {
    if (sender.id !== chrome.runtime.id || !msg || typeof msg.type !== "string" || !msg.type.startsWith("shield-")) return;
    if (!String(sender.url || "").startsWith(chrome.runtime.getURL(""))) return;      // our own pages only
    (async () => {
        try {
            if (msg.type === "shield-get") { syncAdminLists(false); send({ ok: true, state: await shieldState(msg.host, msg.tabId) }); }
            else if (msg.type === "shield-set") {                                      // { key: ads | trackers | popups, value: boolean }
                if (!["ads", "trackers", "popups"].includes(msg.key)) return send({ ok: false, error: "Unknown setting." });
                const s = { ...(await getShields()), [msg.key]: !!msg.value };
                await saveShields(s);
                if (msg.key !== "popups") await applyShields();
                send({ ok: true, state: await shieldState(msg.host, msg.tabId) });
            } else if (msg.type === "shield-site") {                                   // { host, off: boolean }
                const h = cleanHost(msg.host);
                if (!validDomain(h) && !/^[a-z0-9-]+(\.[a-z0-9-]+)*$/.test(h)) return send({ ok: false, error: "Invalid website." });
                const s = await getShields();
                const off = new Set(s.off); if (msg.off) off.add(h); else off.delete(h);
                await saveShields({ ...s, off: [...off].slice(0, 500) });
                await applyShields();
                send({ ok: true, state: await shieldState(h, msg.tabId) });
            } else send({ ok: false, error: "Unknown request." });
        } catch { send({ ok: false, error: "Something went wrong." }); }
    })();
    return true;
});

chrome.runtime.onInstalled.addListener(() => { applyShields().then(() => syncAdminLists(true)); });
chrome.runtime.onStartup?.addListener(() => { applyShields().then(() => syncAdminLists(false)); });
