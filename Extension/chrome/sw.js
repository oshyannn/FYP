// Service worker entry. background.js is loaded unchanged; the sign-in guard is added next to it. If the guard file ever fails to
// load, the rest of the extension keeps working.
importScripts("guard-rules.js", "background.js");
try {
    importScripts("guard-background.js");
} catch (err) {
    console.error("sign-in guard failed to load (the rest of SafeBrowse still works):", err);
}
