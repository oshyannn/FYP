// Sign-in guard, background side. Loaded by sw.js AFTER background.js and uses its helpers (analyze, getSettings, shouldScan,
// mapHas, mapAdd, ICON). Two protections, both only for sites that are not on a trusted list:
//   1. a password form that would send the password to a DIFFERENT website, or a page that pretends to be a brand it is not
//      (the page side, signin-guard.js, pauses the submit and asks here);
//   2. an OAuth "allow this app" request (consent phishing): which permissions, who asks, where the result goes.
// Both ask the person in a small window (guard.html). Switch: the same "Real-Time URL Detection" + "Website Blocking" settings.
"use strict";

const SBG_ASK_MS = 120000;                       // no answer = the safe choice (Don't send / Go back)
const SBG_REMEMBER_MS = 30 * 24 * 3600 * 1000;   // "Always allow" is remembered this long
const sbgPending = new Map();                    // dialog id -> resolve(choice)
const sbgAsked = new Map();                      // "tabId|clientId" -> time of the last question (no repeats while the flow continues)
const sbgLastPage = new Map();                   // tabId -> last normal page of that tab (where an OAuth flow came from)
let sbgSeq = 0;
const sbgLog = (...a) => console.log("[guard]", ...a);

// ---------------------------------------------------------------- helpers
// What do we know about the page the person is on? trusted = on a trusted list AND not a "anyone can publish here" platform.
async function sbgTrust(url) {
    const host = SBG.host(url);
    const shared = SBG.isShared(host);
    if (!shouldScan(url)) return { known: false, trusted: false, bad: false, susp: false, shared, status: "Not checked" };
    let d = null;
    try { d = await analyze(url); } catch { /* backend down: no verdict, the other rules still work */ }
    const has = !!d && d.has_data;
    return {
        known: has, shared,
        trusted: !shared && has && d.status === "Safe" && ["whitelist", "trusted-suffix"].includes(d.source),
        bad: has && (d.status === "Malicious" || d.status === "Restricted"),
        susp: has && d.status === "Suspicious",
        status: has ? d.status : "Unknown",
    };
}

// Open the question window and wait for the answer: "block" | "allow" | "always".
function sbgAsk(kind, params, height) {
    return new Promise((resolve) => {
        const id = ++sbgSeq;
        const keep = setInterval(() => { try { chrome.runtime.getPlatformInfo(() => void chrome.runtime.lastError); } catch {} }, 20000);   // keeps the worker awake
        let timer;
        const finish = (choice) => {
            if (!sbgPending.has(id)) return;
            sbgPending.delete(id);
            clearTimeout(timer);
            clearInterval(keep);
            resolve(choice === "allow" || choice === "always" ? choice : "block");
        };
        sbgPending.set(id, finish);
        timer = setTimeout(() => finish("block"), SBG_ASK_MS);
        const q = new URLSearchParams({ id: String(id), kind, ...params });
        chrome.windows.create({ url: chrome.runtime.getURL("guard.html") + "?" + q, type: "popup", width: 520, height: height || 460, focused: true })
            .catch((err) => { console.error("[guard] could not open the question window, choosing the safe answer:", err); finish("block"); });
    });
}

chrome.runtime.onMessage.addListener((msg, sender) => {       // the question window reports the person's choice
    if (sender.id !== chrome.runtime.id || !msg || msg.type !== "guard-decision") return;
    if (!String(sender.url || "").startsWith(chrome.runtime.getURL("guard.html"))) return;
    const finish = sbgPending.get(Number(msg.id));
    if (finish) finish(msg.choice);
});

async function sbgEnabled() {
    const s = await getSettings();
    return !!(s.realtime && s.blocking);
}

// ---------------------------------------------------------------- 1. password forms
chrome.runtime.onMessage.addListener((msg, sender, send) => {
    if (sender.id !== chrome.runtime.id || !msg || msg.type !== "signin-check" || !sender.tab) return;
    sbgSignin(msg, sender).then(send, (err) => { console.error("[guard] sign-in check failed, allowing:", err); send({ action: "allow", failed: true }); });
    return true;
});

async function sbgSignin(msg, sender) {
    if (!(await sbgEnabled())) return { action: "allow" };
    const pageUrl = String(sender.url || sender.tab.url || "");
    if (!/^https?:/i.test(pageUrl)) return { action: "allow" };
    const pageHost = SBG.host(pageUrl);
    const pageSite = SBG.site(pageHost);
    let target = null;                                          // where the form posts to (null = the same page, or unknown)
    if (typeof msg.action === "string" && /^https?:/i.test(msg.action)) {
        const h = SBG.host(msg.action);
        if (h) target = { host: h, site: SBG.site(h) };
    }
    const cross = !!target && target.site !== pageSite;
    const brand = SBG.brandClaim(msg.claims, pageSite);
    const key = pageSite + ">" + (target ? target.site : pageSite);
    if (await mapHas("sgAllow", key)) return { action: "allow" };
    const trust = await sbgTrust(pageUrl);

    let why = null;
    if (trust.bad) why = "SafeBrowse rates this website as dangerous.";
    else if (cross && !trust.trusted) why = `The password you typed would be sent to a different website (${target.host}), not to ${pageHost}.`;
    else if (brand && !trust.trusted) why = `This page says it is ${brand.name}, but it is not on ${brand.name}'s own website. You are on ${pageHost}.`;
    else if (trust.susp) why = "SafeBrowse rates this website as suspicious, and it is asking for a password.";
    sbgLog("sign-in form", { page: pageHost, postsTo: target && target.host, cross, brand: brand && brand.name, rating: trust.status,
                             trusted: trust.trusted, shared: trust.shared, ask: !!why });
    if (!why) return { action: "allow" };

    const lines = [["You are on", pageHost]];
    if (target) lines.push(["Password would be sent to", target.host]);
    if (brand) lines.push(["Page claims to be", brand.name]);
    lines.push(["SafeBrowse rating", trust.status + (trust.shared ? " (shared hosting platform)" : "")]);
    const choice = await sbgAsk("signin", {
        title: "Check before you sign in", why, lines: JSON.stringify(lines),
        note: "Your password has not been sent yet. Only continue if you are sure this is the real website.",
    }, 440);
    sbgLog("sign-in answer:", choice);
    if (choice === "always") mapAdd("sgAllow", key, SBG_REMEMBER_MS);
    return { action: choice === "block" ? "block" : "allow" };
}

// ---------------------------------------------------------------- 2. OAuth "allow this app"
async function sbgLastPageOf(tabId) {
    if (sbgLastPage.has(tabId)) return sbgLastPage.get(tabId);
    try { return (await chrome.storage.session.get("sbgp" + tabId))["sbgp" + tabId] || null; } catch { return null; }
}
async function sbgInitiator(tabId) {                             // the page the person came from (a popup: the page that opened it)
    let from = await sbgLastPageOf(tabId);
    if (!from) {
        const tab = await chrome.tabs.get(tabId).catch(() => null);
        if (tab && tab.openerTabId != null) from = await sbgLastPageOf(tab.openerTabId);
    }
    return from;
}
async function sbgLeave(tabId, fromUrl) {                        // "Go back": close the popup, or return the tab to where it was
    const tab = await chrome.tabs.get(tabId).catch(() => null);
    if (!tab) return;
    if (tab.openerTabId != null) chrome.tabs.remove(tabId).catch(() => {});
    else chrome.tabs.update(tabId, { url: fromUrl }).catch(() => {});
}

chrome.webNavigation?.onCommitted.addListener(async (d) => {
    if (d.frameId !== 0 || !/^https?:/i.test(d.url)) return;
    const oa = SBG.parseOAuth(d.url);
    if (!oa) {                                                    // a normal page: remember it as "where this tab was"
        sbgLastPage.set(d.tabId, d.url);
        try { chrome.storage.session.set({ ["sbgp" + d.tabId]: d.url }).catch(() => {}); } catch {}
        return;
    }
    try { await sbgOAuth(d, oa); } catch (err) { console.error("[guard] OAuth check failed:", err); }
});
chrome.tabs?.onRemoved.addListener((tabId) => {
    sbgLastPage.delete(tabId);
    try { chrome.storage.session.remove("sbgp" + tabId).catch(() => {}); } catch {}
});

async function sbgOAuth(d, oa) {
    if (!(await sbgEnabled())) return;
    const fromUrl = await sbgInitiator(d.tabId);
    if (!fromUrl) return;                                         // typed in the address bar / bookmark: the person started it
    const fromHost = SBG.host(fromUrl);
    const fromSite = SBG.site(fromHost);
    if (fromSite === SBG.site(oa.host)) return;                   // already on the provider's own website
    const key = fromSite + "|" + oa.provider + "|" + oa.clientId;
    if (await mapHas("oauthAllow", key)) return;
    const trust = await sbgTrust(fromUrl);
    const elsewhere = !!oa.redirectSite && oa.redirectSite !== fromSite;
    let why = null;
    if (trust.trusted) why = null;                                // a trusted website asking for access: not interrupted
    else if (trust.bad) why = "SafeBrowse rates the website that sent you here as dangerous.";
    else if (trust.susp) why = "SafeBrowse rates the website that sent you here as suspicious.";
    else if (oa.maxTier === "high") why = "This asks for powerful access to your account.";
    else if (oa.maxTier === "medium") why = "This asks for more than basic sign-in, from a website that is not on a trusted list.";
    else if (elsewhere) why = "Basic sign-in, but the result would be sent to a different website than the one you were on.";
    sbgLog("OAuth request", { from: fromHost, provider: oa.provider, tier: oa.maxTier, redirectTo: oa.redirectHost, rating: trust.status,
                              trusted: trust.trusted, ask: !!why });
    if (!why) return;

    const askKey = d.tabId + "|" + oa.clientId;                   // the flow commits several pages: ask once
    if (Date.now() - (sbgAsked.get(askKey) || 0) < SBG_ASK_MS) return;
    sbgAsked.set(askKey, Date.now());
    if (sbgAsked.size > 200) sbgAsked.clear();

    const lines = [["Website asking", fromHost], ["Account", oa.providerName]];
    for (const s of oa.scopes.slice(0, 8)) lines.push(["Permission", s.text, s.tier]);
    if (oa.scopes.length > 8) lines.push(["Permission", "and " + (oa.scopes.length - 8) + " more", "medium"]);
    if (oa.redirectHost) lines.push(["Result is sent to", oa.redirectHost]);
    lines.push(["App ID", oa.clientId.slice(0, 48)]);
    const choice = await sbgAsk("oauth", {
        title: "A website wants access to your " + oa.providerName + " account", why, lines: JSON.stringify(lines),
        note: "Nothing has been shared yet. If you did not start this on purpose, go back.",
    }, 560);
    sbgLog("OAuth answer:", choice);
    if (choice === "always") mapAdd("oauthAllow", key, SBG_REMEMBER_MS);
    else if (choice === "block") sbgLeave(d.tabId, fromUrl);
}
