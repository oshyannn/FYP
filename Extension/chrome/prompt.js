const p = new URLSearchParams(location.search);
const id = Number(p.get("id"));
const hosts = (p.get("hosts") || "").split(",").filter(Boolean);
document.getElementById("file").textContent = p.get("file") || "(unnamed file)";
document.getElementById("from").textContent = "From: " + (p.get("from") || "unknown") + (p.get("page") ? "   ·   You were on: " + p.get("page") : "");
document.getElementById("why").textContent = p.get("why") || "";
if (p.get("trusted") === "1") document.getElementById("trust").textContent = "This site is on your trusted list, so it is not blocked outright, but you should still decide.";

let done = false;
function decide(choice) {
    if (done) return;
    done = true;
    try { chrome.runtime.sendMessage({ type: "prompt-decision", id, choice, hosts }); } catch {}
    setTimeout(() => window.close(), 50);
}
document.getElementById("block").onclick = () => decide("block");
document.getElementById("allow").onclick = () => decide("allow");
document.getElementById("always").onclick = () => decide("always");
window.addEventListener("beforeunload", () => decide("block"));   // closing the window = Block
setTimeout(() => decide("block"), 60000);                         // no answer = Block
