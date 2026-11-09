// Shared rules for the sign-in guard: registered domain, shared-hosting platforms, brand -> official websites, and a reader for
// OAuth "allow this app" links (Google, Microsoft, GitHub, Facebook, Apple). Pure functions: no chrome.* calls, no network.
// Loaded twice: by sw.js (importScripts, the background side) and by the page (manifest.json content script).
var SBG = (() => {
    "use strict";

    const TWO_LEVEL = new Set(["com", "co", "org", "net", "gov", "edu", "ac"]);
    const host = (u) => { try { return new URL(u).hostname.toLowerCase(); } catch { return ""; } };
    // registered domain: good enough for .com / .co.uk / .com.my (the same rule background.js uses); IP addresses stay whole
    function site(h) {
        h = String(h || "").toLowerCase();
        if (/^\d{1,3}(\.\d{1,3}){3}$/.test(h)) return h;
        const p = h.replace(/^www\./, "").split(".").filter(Boolean);
        if (p.length <= 2) return p.join(".");
        return p.slice(TWO_LEVEL.has(p[p.length - 2]) && p[p.length - 1].length === 2 ? -3 : -2).join(".");
    }

    // Platforms where ANYONE can publish a page under a well-known name. A trusted name here does not make the page trustworthy.
    const SHARED_HOSTS = [
        "sites.google.com", "docs.google.com", "forms.gle", "drive.google.com", "storage.googleapis.com", "googleusercontent.com",
        "github.io", "githubusercontent.com", "gitlab.io", "blogspot.com", "wordpress.com", "weebly.com", "wixsite.com", "wix.com",
        "netlify.app", "vercel.app", "pages.dev", "workers.dev", "web.app", "firebaseapp.com", "herokuapp.com", "glitch.me",
        "replit.app", "repl.co", "notion.site", "carrd.co", "000webhostapp.com", "azurewebsites.net", "appspot.com",
        "s3.amazonaws.com", "onrender.com", "fly.dev", "surge.sh", "ipfs.io", "typeform.com", "webflow.io", "framer.website",
    ];
    const isShared = (h) => SHARED_HOSTS.some((s) => h === s || h.endsWith("." + s));

    // A page that names one of these brands in its title / headings, but is not on one of the brand's own websites.
    const BRANDS = [
        { name: "Google", words: ["google", "gmail", "google account"], domains: ["google.com", "gmail.com", "youtube.com", "google.com.my", "google.co.uk", "google.co.in"] },
        { name: "Microsoft", words: ["microsoft", "outlook", "office 365", "office365", "onedrive", "microsoft 365"], domains: ["microsoft.com", "live.com", "office.com", "microsoftonline.com", "outlook.com", "office365.com", "microsoft365.com", "sharepoint.com", "onedrive.com", "windows.com", "bing.com", "msn.com", "xbox.com", "skype.com"] },
        { name: "Apple", words: ["apple id", "icloud", "apple account"], domains: ["apple.com", "icloud.com"] },
        { name: "Facebook", words: ["facebook"], domains: ["facebook.com", "fb.com", "messenger.com", "meta.com"] },
        { name: "Instagram", words: ["instagram"], domains: ["instagram.com"] },
        { name: "PayPal", words: ["paypal"], domains: ["paypal.com", "paypal.me", "paypalobjects.com"] },
        { name: "Amazon", words: ["amazon"], domains: ["amazon.com", "amazon.co.uk", "amazon.de", "amazon.fr", "amazon.in", "amazon.sg", "amazon.com.au", "amazon.co.jp", "amazon.ca"] },
        { name: "Netflix", words: ["netflix"], domains: ["netflix.com"] },
        { name: "GitHub", words: ["github"], domains: ["github.com"] },
        { name: "LinkedIn", words: ["linkedin"], domains: ["linkedin.com"] },
        { name: "Twitter / X", words: ["twitter"], domains: ["twitter.com", "x.com"] },
        { name: "Dropbox", words: ["dropbox"], domains: ["dropbox.com"] },
        { name: "Steam", words: ["steam community", "steam login", "steam"], domains: ["steampowered.com", "steamcommunity.com"] },
        { name: "Binance", words: ["binance"], domains: ["binance.com"] },
        { name: "Coinbase", words: ["coinbase"], domains: ["coinbase.com"] },
        { name: "TikTok", words: ["tiktok"], domains: ["tiktok.com"] },
        { name: "Maybank", words: ["maybank", "maybank2u"], domains: ["maybank2u.com.my", "maybank.com", "maybank.com.my", "maybank2u.com", "maybank.com.sg"] },
        { name: "CIMB", words: ["cimb", "cimb clicks"], domains: ["cimbclicks.com.my", "cimb.com.my", "cimbbank.com.my", "cimb.com"] },
        { name: "Public Bank", words: ["public bank"], domains: ["pbebank.com", "publicbank.com.my"] },
        { name: "RHB", words: ["rhb"], domains: ["rhbgroup.com", "rhbbank.com.my"] },
        { name: "Hong Leong Bank", words: ["hong leong"], domains: ["hlb.com.my", "hongleong.com.my"] },
        { name: "HSBC", words: ["hsbc"], domains: ["hsbc.com", "hsbc.com.my"] },
        { name: "Touch 'n Go", words: ["touch n go", "touchngo", "tng"], domains: ["touchngo.com.my", "tngdigital.com.my"] },
        { name: "Shopee", words: ["shopee"], domains: ["shopee.com", "shopee.com.my", "shopee.sg"] },
        { name: "Lazada", words: ["lazada"], domains: ["lazada.com", "lazada.com.my", "lazada.sg"] },
    ];
    // text = the page's title and headings. Returns { name } when the page names a brand it does not belong to.
    function brandClaim(text, pageSite) {
        const t = " " + String(text || "").toLowerCase().replace(/[^a-z0-9]+/g, " ") + " ";
        for (const b of BRANDS) {
            if (!b.words.some((w) => t.includes(" " + w + " "))) continue;
            if (b.domains.some((d) => pageSite === d || pageSite.endsWith("." + d))) continue;
            return { name: b.name };
        }
        return null;
    }

    // ---------------------------------------------------------------- OAuth "allow this app" links
    const RANK = { low: 0, medium: 1, high: 2 };
    const GOOGLE = [
        [/^openid$/, "low", "Know who you are (sign-in)"],
        [/^(email|.*userinfo\.email)$/, "low", "See your email address"],
        [/^(profile|.*userinfo\.profile)$/, "low", "See your name and profile picture"],
        [/mail\.google\.com|\/auth\/gmail/, "high", "Read, send or delete your Gmail"],
        [/\/auth\/drive\.(file|appdata|metadata)/, "medium", "See files or file names in your Google Drive"],
        [/\/auth\/drive/, "high", "See, edit or delete your Google Drive files"],
        [/\/auth\/(spreadsheets|documents|presentations)/, "high", "Read or edit your Google Docs, Sheets or Slides"],
        [/\/auth\/calendar/, "medium", "See or edit your calendar"],
        [/\/auth\/contacts|m8\/feeds|\/auth\/directory/, "medium", "See your contacts"],
        [/photoslibrary|\/auth\/photos/, "medium", "See your Google Photos"],
        [/\/auth\/youtube/, "medium", "Manage your YouTube account"],
        [/cloud-platform|\/auth\/admin|\/auth\/compute|\/auth\/devstorage/, "high", "Manage Google Cloud or administrator settings"],
    ];
    const MICROSOFT = [
        [/^(openid|profile|email|user\.read)$/, "low", "Know who you are and see your basic profile"],
        [/^offline_access$/, "medium", "Keep access after you leave (stay signed in)"],
        [/^(mail\.|mailboxsettings\.)/, "high", "Read, send or delete your email"],
        [/^(files\.|sites\.)/, "high", "Read or change your files (OneDrive / SharePoint)"],
        [/^(directory\.|application\.|user\.readwrite)|full_access_as_app|^\.default$/, "high", "Read or change accounts in your organisation"],
        [/^(contacts\.|calendars\.)/, "medium", "See or edit your contacts and calendar"],
        [/^user\.read(basic)?\.all$/, "medium", "See other people in your organisation"],
    ];
    const GITHUB = [
        [/^(read:user|user:email)$/, "low", "See your GitHub profile and email address"],
        [/^repo$/, "high", "Full access to your private and public repositories"],
        [/^(delete_repo|admin:|workflow|write:packages|delete:packages|write:public_key|write:gpg_key)/, "high", "Change or delete repositories, workflows or keys"],
        [/^(repo:|public_repo)/, "medium", "Access your repositories"],
        [/^user$/, "medium", "See and change your GitHub profile"],
        [/^(gist|notifications|read:org|write:org|read:discussion|write:discussion)$/, "medium", "Access gists, notifications or organisations"],
    ];
    const FACEBOOK = [
        [/^(public_profile|email)$/, "low", "See your public profile and email address"],
        [/^(pages_|ads_|business_management|publish_|manage_|instagram_|whatsapp_)/, "high", "Manage your pages or ads, or post for you"],
    ];
    const APPLE = [[/^(name|email)$/, "low", "See your name and email address"]];

    const PROVIDERS = [
        { id: "google", name: "Google", split: /\s+/, rules: GOOGLE,
          test: (u) => u.hostname === "accounts.google.com" && /^\/o\/oauth2\/(v2\/)?(auth|authorize)/.test(u.pathname) },
        { id: "microsoft", name: "Microsoft", split: /\s+/, rules: MICROSOFT, lastSegment: true,
          test: (u) => (u.hostname === "login.microsoftonline.com" || u.hostname === "login.live.com") && /\/oauth2\/(v2\.0\/)?authorize/.test(u.pathname) },
        { id: "github", name: "GitHub", split: /[\s,]+/, rules: GITHUB, emptyIsLow: "See your public GitHub profile",
          test: (u) => u.hostname === "github.com" && u.pathname === "/login/oauth/authorize" },
        { id: "facebook", name: "Facebook", split: /[\s,]+/, rules: FACEBOOK,
          test: (u) => /^(www|m|web)\.facebook\.com$/.test(u.hostname) && /\/dialog\/oauth/.test(u.pathname) },
        { id: "apple", name: "Apple", split: /[\s,]+/, rules: APPLE,
          test: (u) => u.hostname === "appleid.apple.com" && u.pathname === "/auth/authorize" },
    ];

    function classify(p, scope) {
        const s = p.lastSegment ? scope.split("/").pop().toLowerCase() : scope.toLowerCase();
        for (const [rx, tier, text] of p.rules) if (rx.test(s)) return { scope, tier, text };
        return { scope, tier: "medium", text: "An unrecognised permission (" + scope.slice(0, 80) + ")" };
    }

    // Returns null when the address is not an OAuth "allow this app" request of a known provider.
    function parseOAuth(rawUrl) {
        let u;
        try { u = new URL(rawUrl); } catch { return null; }
        const p = PROVIDERS.find((x) => x.test(u));
        if (!p) return null;
        const clientId = (u.searchParams.get("client_id") || u.searchParams.get("clientid") || "").slice(0, 200);
        if (!clientId) return null;
        const redirectUri = (u.searchParams.get("redirect_uri") || "").slice(0, 500);
        const scopes = (u.searchParams.get("scope") || "").split(p.split).filter(Boolean).slice(0, 40).map((s) => classify(p, s));
        if (!scopes.length && p.emptyIsLow) scopes.push({ scope: "", tier: "low", text: p.emptyIsLow });
        const redirectHost = redirectUri ? host(redirectUri) : "";
        const maxTier = scopes.reduce((m, s) => (RANK[s.tier] > RANK[m] ? s.tier : m), "low");
        return { provider: p.id, providerName: p.name, host: u.hostname, clientId, redirectUri, redirectHost,
                 redirectSite: site(redirectHost), scopes, maxTier };
    }

    return { host, site, isShared, brandClaim, parseOAuth, RANK };
})();
