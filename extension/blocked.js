const p = new URLSearchParams(location.search);
const target = p.get("url") || "";
let safeTarget = null;
try {
    const u = new URL(target);
    if (u.protocol === "http:" || u.protocol === "https:") safeTarget = u.href;   // never navigate to javascript: etc.
} catch {}

document.getElementById("url").textContent = target;           // textContent: page text is never parsed as HTML
document.getElementById("score").textContent = p.get("score") || "?";
if (p.get("kind") === "adult") {
    document.getElementById("title").textContent = "Adult content blocked";
    document.getElementById("lead").textContent = "This site is on your adult-content block list.";
}
let reasons = [];
try { reasons = JSON.parse(p.get("reasons") || "[]"); } catch {}
for (const r of reasons) {
    const li = document.createElement("li");
    li.textContent = String(r);
    document.getElementById("reasons").appendChild(li);
}

document.getElementById("leave").onclick = () => chrome.tabs.update({ url: "chrome://newtab/" });

document.getElementById("proceed").onclick = async () => {
    if (!safeTarget) return;
    const host = new URL(safeTarget).hostname;
    const s = await chrome.storage.session.get("allowed");
    const allowed = new Set(s.allowed || []);
    allowed.add(host);
    await chrome.storage.session.set({ allowed: [...allowed] });   // allowed until the browser closes
    location.replace(safeTarget);
};
