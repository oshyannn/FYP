// Sign-in guard, page side. When a person submits a form with a password they typed, the submit is held for a moment and the
// extension decides: allow at once, or ask the person first (the password would go to a different website, or the page pretends
// to be a brand it is not). The extension is sent ONLY: the address the form posts to (no query string), and the page's title and
// headings. The password and everything else typed is never read or sent. If the extension cannot answer, the form is sent as usual.
(() => {
    if (window.__sbSigninGuard) return;
    window.__sbSigninGuard = true;
    const approved = new WeakSet();
    const waiting = new WeakSet();

    // where the form posts to; read from the attributes, because a field named "action" would hide form.action
    function postTarget(form, submitter) {
        const raw = (submitter && submitter.getAttribute && submitter.getAttribute("formaction")) || form.getAttribute("action") || "";
        if (/^\s*javascript:/i.test(raw)) return null;
        try {
            const u = new URL(raw, document.baseURI);
            return u.protocol === "http:" || u.protocol === "https:" ? u.origin + u.pathname : null;
        } catch { return null; }
    }
    function claims() {                                           // what the page calls itself
        const parts = [document.title || ""];
        for (const sel of ["h1", "h2", "meta[property='og:site_name']", "meta[name='application-name']"]) {
            for (const el of Array.from(document.querySelectorAll(sel)).slice(0, 4)) parts.push(el.content || el.textContent || "");
        }
        return parts.join(" | ").replace(/\s+/g, " ").slice(0, 600);
    }
    const typedPassword = (form) => Array.from(form.querySelectorAll('input[type="password"]')).some((i) => i.value);

    document.addEventListener("submit", async (ev) => {
        const form = ev.target;
        if (!(form instanceof HTMLFormElement) || approved.has(form) || !typedPassword(form)) return;
        ev.preventDefault();
        ev.stopImmediatePropagation();                            // the page's own handlers run when the submit is repeated below
        if (waiting.has(form)) return;                            // a question is already open for this form
        waiting.add(form);
        let reply = { action: "allow" };
        try {
            reply = (await chrome.runtime.sendMessage({ type: "signin-check", action: postTarget(form, ev.submitter), claims: claims() })) || reply;
        } catch { /* the extension was reloaded or is not answering: do not get in the way */ }
        waiting.delete(form);
        if (reply.action === "block") return;                     // the person chose not to send it
        approved.add(form);
        try { form.requestSubmit(ev.submitter || undefined); }
        catch { try { form.submit(); } catch {} }
    }, true);
})();
