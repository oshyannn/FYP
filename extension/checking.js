const target = new URLSearchParams(location.search).get("url") || "";
let ok = false;
try {
    const u = new URL(target);
    ok = u.protocol === "http:" || u.protocol === "https:";
} catch {}
document.getElementById("url").textContent = target;
document.getElementById("cancel").onclick = () => chrome.tabs.update({ url: "chrome://newtab/" });

if (ok) {
    chrome.runtime.sendMessage({ type: "verify", url: target }, (res) => {
        if (chrome.runtime.lastError || !res) {
            document.getElementById("msg").textContent = "The check failed, opening the page without a verdict.";
            setTimeout(() => location.replace(target), 1500);
            return;
        }
        if (res.action === "block") location.replace(res.blockedUrl);
        else location.replace(target);              // verdict fetched: the next navigation is answered from cache
    });
}
