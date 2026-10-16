console.log("Background running...");

// avoid duplicate scanning
let lastURL = "";

const ICON = chrome.runtime.getURL("icons/icon128.png");

// Only public http(s) pages should ever be sent to the backend.
// Anything else (extension pages, localhost, private network, internal
// app URLs) is skipped so private URLs never leave the browser.
function shouldScan(rawUrl) {
    let u;
    try {
        u = new URL(rawUrl);
    } catch {
        return false;
    }

    if (u.protocol !== "http:" && u.protocol !== "https:") return false;

    const host = u.hostname;
    if (host === "localhost" || host === "127.0.0.1" || host === "::1") return false;
    if (/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(host)) return false;
    if (!host.includes(".")) return false;           // intranet-style hostnames

    // Pages that carry private account/session content
    if (host === "claude.ai" || host.endsWith(".claude.ai")) return false;

    return true;
}

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {

    // only when page fully loaded
    if (changeInfo.status !== "complete") return;

    if (!tab.url) return;

    if (!shouldScan(tab.url)) return;

    // prevent duplicate API calls
    if (tab.url === lastURL) return;

    lastURL = tab.url;

    console.log("Scanning URL:", tab.url);

    // CALL YOUR FLASK API
    fetch("http://127.0.0.1:5000/analyze", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({
            url: tab.url
        })
    })
    .then(res => res.json())
    .then(data => {

        console.log("API Result:", data);

        // Backend response shape:
        // {
        //   status: "Safe" | "Suspicious" | "Malicious" | "Unknown",
        //   risk_score: 0-100,
        //   has_data: true | false,   // false = no provider had an opinion at all
        //   match_scope: "exact" | "domain" | null,
        //   ...
        // }
        //
        // When has_data is false, detail_url / match_scope / matched_url /
        // phish_id are all null by design: there is no matching record to
        // describe. risk_score is just a placeholder, NOT a clean bill of health.

        if (!data.has_data) {
            console.log("No data from any provider for this URL — not flagged, but not confirmed safe either.");
            return;
        }

        if (data.status === "Malicious") {
            chrome.notifications.create({
                type: "basic",
                iconUrl: ICON,
                title: "⚠ Security Warning",
                message: data.match_scope === "domain"
                    ? "This domain is a known phishing site (different page confirmed)."
                    : "This exact page is a confirmed phishing site!"
            });
            return;
        }

        if (data.status === "Suspicious") {
            chrome.notifications.create({
                type: "basic",
                iconUrl: ICON,
                title: "⚠ Caution",
                message: "This site shows signs of risk. Proceed carefully."
            });
            return;
        }

        // status === "Safe": has_data is true AND no provider flagged it.
        console.log("Checked and no threats found.");

    })
    .catch(err => {
        console.error("API error:", err);
    });

});