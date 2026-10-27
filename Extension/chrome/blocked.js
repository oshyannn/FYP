const p = new URLSearchParams(location.search);
const target = p.get("url") || "";
let safeTarget = null;
try {
    const u = new URL(target);
    if (u.protocol === "http:" || u.protocol === "https:") safeTarget = u.href;   // never navigate to javascript: etc.
} catch {}
const $ = (id) => document.getElementById(id);

$("url").textContent = target;                                  // textContent: page text is never parsed as HTML
const score = Math.max(0, Math.min(100, Number(p.get("score")) || 0));
$("score").textContent = p.get("score") ? String(Math.round(score)) : "?";
$("bar").style.width = score + "%";
if (p.get("kind") === "adult") {
    document.title = "Adult content blocked - SafeBrowse";
    $("title").textContent = "Adult Content Blocked";
    $("lead").textContent = "This site is on your adult-content block list.";
}
let reasons = [];
try { reasons = JSON.parse(p.get("reasons") || "[]"); } catch {}
if (!Array.isArray(reasons) || !reasons.length) $("reasons").parentElement.classList.add("hidden");
for (const r of Array.isArray(reasons) ? reasons : []) {
    const li = document.createElement("li");
    li.textContent = String(r);
    $("reasons").appendChild(li);
}

$("leave").onclick = () => chrome.tabs.update({ url: "chrome://newtab/" });

// Same two-step "Continue" as the Figma design: ask once more before opening a dangerous site.
$("proceed").onclick = () => { $("main-actions").classList.add("hidden"); $("confirm").classList.remove("hidden"); };
$("cancel").onclick = () => { $("confirm").classList.add("hidden"); $("main-actions").classList.remove("hidden"); };
$("yes").onclick = async () => {
    if (!safeTarget) return;
    const host = new URL(safeTarget).hostname;
    const s = await chrome.storage.session.get("allowed");
    const allowed = new Set(s.allowed || []);
    allowed.add(host);
    await chrome.storage.session.set({ allowed: [...allowed] });   // allowed until the browser closes
    location.replace(safeTarget);
};
