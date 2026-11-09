// The question window of the sign-in guard. Everything shown comes from the address of this window and is written with
// textContent only (a website controls some of these words, so they are never treated as HTML).
const p = new URLSearchParams(location.search);
const id = Number(p.get("id"));
const kind = p.get("kind") === "oauth" ? "oauth" : "signin";

document.getElementById("title").textContent = p.get("title") || "Check before you continue";
document.getElementById("why").textContent = p.get("why") || "";
document.getElementById("note").textContent = p.get("note") || "";
document.title = "SafeBrowse check";

let lines = [];
try { lines = JSON.parse(p.get("lines") || "[]"); } catch {}
const ul = document.getElementById("lines");
for (const row of Array.isArray(lines) ? lines.slice(0, 20) : []) {
    if (!Array.isArray(row)) continue;
    const li = document.createElement("li");
    const k = document.createElement("span");
    k.className = "k";
    k.textContent = String(row[0] ?? "");
    const v = document.createElement("span");
    v.className = "v";
    v.textContent = String(row[1] ?? "");
    if (["high", "medium", "low"].includes(row[2])) {
        const tag = document.createElement("span");
        tag.className = "tag " + row[2];
        tag.textContent = row[2].toUpperCase();
        v.appendChild(tag);
    }
    li.append(k, v);
    ul.appendChild(li);
}

const LABELS = kind === "oauth"
    ? { block: "Go back", allow: "Continue", always: "Always allow this app" }
    : { block: "Don't send", allow: "Send anyway", always: "Always allow this" };
for (const [b, text] of Object.entries(LABELS)) document.getElementById(b).textContent = text;

let done = false;
function decide(choice) {
    if (done) return;
    done = true;
    try { chrome.runtime.sendMessage({ type: "guard-decision", id, choice }); } catch {}
    setTimeout(() => window.close(), 50);
}
document.getElementById("block").onclick = () => decide("block");
document.getElementById("allow").onclick = () => decide("allow");
document.getElementById("always").onclick = () => decide("always");
window.addEventListener("beforeunload", () => decide("block"));   // closing the window = the safe choice
setTimeout(() => decide("block"), 120000);                        // no answer = the safe choice
