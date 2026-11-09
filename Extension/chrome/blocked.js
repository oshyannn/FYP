const p = new URLSearchParams(location.search);
const target = p.get("url") || "";
let safeTarget = null;
try {
    const u = new URL(target);
    if (u.protocol === "http:" || u.protocol === "https:") safeTarget = u.href;   // never navigate to javascript: etc.
} catch {}
const $ = (id) => document.getElementById(id);
const kind = p.get("kind");

$("url").textContent = target;                                  // textContent: page text is never parsed as HTML
const score = Math.max(0, Math.min(100, Number(p.get("score")) || 0));
$("score").textContent = p.get("score") ? String(Math.round(score)) : "?";
$("bar").style.width = score + "%";
if (kind === "adult") {
    document.title = "Adult content blocked - SafeBrowse";
    $("title").textContent = "Adult Content Blocked";
    $("lead").textContent = "This site is on your adult-content block list.";
}
if (kind === "userblock") {                                     // the person's own "always block" rule
    document.title = "Website blocked by you - SafeBrowse";
    $("title").textContent = "You Blocked This Website";
    $("lead").textContent = "You chose to always block this website. You can change that here or in the SafeBrowse popup, Site settings.";
    $("bar").closest(".score").classList.add("hidden");
}
let reasons = [];
try { reasons = JSON.parse(p.get("reasons") || "[]"); } catch {}
if (kind === "userblock" || !Array.isArray(reasons) || !reasons.length) $("reasons").parentElement.classList.add("hidden");
for (const r of Array.isArray(reasons) ? reasons : []) {
    const li = document.createElement("li");
    li.textContent = String(r);
    $("reasons").appendChild(li);
}

let host = "";
try { host = new URL(safeTarget).hostname; } catch {}
$("host").textContent = host;

// The background script owns the rules and the token (siterules.js); this page only asks it.
function setSite(mode) {
    return new Promise((resolve) => {
        try { chrome.runtime.sendMessage({ type: "site-set", host, mode }, (r) => resolve(r || { ok: false, error: "The extension did not answer. Reload it and try again." })); }
        catch { resolve({ ok: false, error: "The extension did not answer. Reload it and try again." }); }
    });
}

$("leave").onclick = $("ub-leave").onclick = () => chrome.tabs.update({ url: "chrome://newtab/" });

if (kind === "userblock") {
    $("main-actions").classList.add("hidden");
    $("userblock-actions").classList.remove("hidden");
    $("ub-remove").onclick = async () => {
        if (!safeTarget) return;
        const r = await setSite("ask");                         // removes the rule; the next visit is checked like any other
        if (!r.ok) { $("ub-err").textContent = r.error || "Could not remove the block."; $("ub-err").classList.remove("hidden"); return; }
        location.replace(safeTarget);
    };
}

// Same two-step "Continue" as the Figma design: ask once more before opening a dangerous site, and ask for how long.
$("proceed").onclick = () => { $("main-actions").classList.add("hidden"); $("confirm").classList.remove("hidden"); refresh(); };
$("cancel").onclick = () => { $("confirm").classList.add("hidden"); $("main-actions").classList.remove("hidden"); };
const choice = () => (document.querySelector('input[name="dur"]:checked') || {}).value || "once";
function refresh() {
    const always = choice() === "allow";
    $("sure").classList.toggle("hidden", !always);                // "always" needs one more confirmation
    if (!always) $("sure-box").checked = false;
    $("yes").textContent = always ? "Yes, always allow this website" : "Continue anyway (unsafe)";
    $("yes").disabled = always && !$("sure-box").checked;
    $("err").classList.add("hidden");
}
$("choices").addEventListener("change", refresh);
$("sure-box").addEventListener("change", refresh);
$("yes").onclick = async () => {
    if (!safeTarget) return;
    const mode = choice();
    if (mode === "allow" && !$("sure-box").checked) return;
    $("yes").disabled = true;
    const r = await setSite(mode);
    if (!r.ok) {                                                  // "always" is saved to the account: it needs the server
        $("err").textContent = r.error || "Could not save your choice.";
        $("err").classList.remove("hidden");
        $("yes").disabled = false;
        return;
    }
    location.replace(safeTarget);
};
