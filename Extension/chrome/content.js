// Tells the extension that a PERSON really clicked or pressed Enter/Space (event.isTrusted), so downloads that start
// right afterwards can be told apart from downloads a page starts by itself. It reads no page content and sends
// nothing but "a gesture happened" (the extension adds the page's host name itself). Scripts cannot fake isTrusted.
(() => {
    let last = 0;
    const report = (e) => {
        if (!e.isTrusted) return;
        if (e.type === "keydown" && e.key !== "Enter" && e.key !== " ") return;
        const now = Date.now();
        if (now - last < 400) return;                 // a few messages per second at most
        last = now;
        try { chrome.runtime.sendMessage({ type: "gesture" }); } catch {}   // throws after the extension was reloaded
    };
    for (const ev of ["pointerdown", "mousedown", "click", "keydown", "touchstart"]) {
        window.addEventListener(ev, report, { capture: true, passive: true });
    }
})();
