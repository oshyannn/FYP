# Sign-in guard (extension) — install, run, test

Extract this zip INTO your FYP folder (merge). Delete this file afterwards. Nothing in the backend, the desktop app or the
database changes. background.js is NOT touched.

## What it does
1. Password form guard: when you press Sign in on a page where you typed a password, SafeBrowse checks WHERE the password goes.
   It asks you first when (and the page is not on a trusted list):
     - the form sends the password to a DIFFERENT website than the one you are on, or
     - the page's title / headings say it is a known brand (Google, Microsoft, Maybank, PayPal ...) but it is not on that brand's website, or
     - SafeBrowse already rates the page Suspicious / dangerous.
   Pages on a trusted list are not interrupted. Platforms where anyone can publish (sites.google.com, github.io, blogspot ...) are
   NOT treated as trusted, even though the name is on a list.
2. "Allow this app" (OAuth) guard: when a website sends you to Google / Microsoft / GitHub / Facebook / Apple to allow an app, it reads the
   address: the permissions (Gmail, Drive, files, repositories ... marked HIGH / MEDIUM / LOW), who is asking, and where the result goes.
   It asks you when the asking website is not trusted and the permissions are powerful or the result goes to a different website.
   An ordinary "Sign in with Google" (basic permissions, result back to the same site) is not interrupted.
Choices in the window: Don't send / Send anyway / Always allow this   (OAuth: Go back / Continue / Always allow this app).
No answer within 2 minutes, or closing the window = the safe choice. "Always allow" is remembered for 30 days.
It uses your existing popup switches: Real-Time URL Detection AND Website Blocking must be ON.

## Files
NEW  Extension/chrome/sw.js               service worker entry (loads background.js unchanged, then the guard)
NEW  Extension/chrome/guard-rules.js      domains, brand list, shared-hosting list, OAuth reader and permission table
NEW  Extension/chrome/guard-background.js the decisions and the question window logic
NEW  Extension/chrome/signin-guard.js     page side: pauses the submit, asks the extension
NEW  Extension/chrome/guard.html / guard.js   the question window
NEW  Extension/testsite/signin-guard/     test pages + serve.py (a pretend scammer's server)
EDIT Extension/chrome/manifest.json       version 1.2.0; service_worker -> sw.js; content script list adds guard-rules.js + signin-guard.js
     (replace the file; if you changed it locally, change only those two places by hand)

## HOW TO MAKE IT WORK
1. Replace the files (extract the zip into FYP).
2. Chrome -> address bar: chrome://extensions -> SafeBrowse -> click the reload arrow.
   If a red "Errors" button appears, click it and send me a screenshot.
3. Make sure the backend is running (python app.py) and the extension is paired (no red "!" on its icon).
   The guard's cross-site and brand rules work even without the backend; the "trusted site" and "Suspicious" parts need it.
4. Open the log: on the SafeBrowse card click the blue "service worker" link -> Console. Lines starting with [guard] explain every decision.
5. Start the test pages: VS Code terminal ->
       cd Extension\testsite\signin-guard
       python serve.py
   then open http://localhost:8000/  in Chrome (type localhost, not 127.0.0.1) and follow the table on that page.
   IMPORTANT: reload each test page after reloading the extension (the page-side script only attaches to pages loaded after that).
6. Real-world checks (no server needed): sign in to github.com (no window), use "Sign in with Google" on an ordinary site (no window).

## What to send me
- Which tests (A1-A4, B1-B6, C1-C2) behaved as the table says, and which did not.
- A screenshot of each question window.
- The [guard] lines from the service worker console, and any red error.
- The text printed in the serve.py terminal (it shows whether the "scammer" received the form; passwords are shown as a length only).

## Troubleshooting
- No window at all: popup switches ON? extension reloaded AND the page reloaded? Look for [guard] lines. If there are none for a submit,
  the page did not fire a normal submit event (see limits).
- Window every time you test: choose Always allow once, or clear: in the service worker console run
      chrome.storage.local.remove(["sgAllow","oauthAllow"])
- Service worker "inactive": click the link anyway, or press Sign in once; it wakes up.
- Undo: put the old manifest.json back (git checkout Extension/chrome/manifest.json) and reload the extension. The new files can stay.

## What it does NOT cover (be honest in the report)
- Logins done by JavaScript (fetch / XMLHttpRequest) or a form.submit() call: no submit event, so no pause. Most phishing kits use a normal form.
- What a scammer's server does with data AFTER it receives it: invisible to us. The guard acts BEFORE the data leaves.
- A page that draws a fake browser pop-up (a fake address bar inside the page): only the brand rule can notice it.
- OAuth: five providers (Google, Microsoft, GitHub, Facebook, Apple); the brand list is short and is plain data in guard-rules.js (easy to extend).
- Card numbers / OTP fields are not watched yet, only password fields.
Privacy: the page side sends the extension only the address the form posts to (without its query string) and the page's title and
headings, inside the browser. The typed password is never read or sent. Nothing new goes to the SafeBrowse server.

## file_structure.md — add these
Extension/chrome: sw.js (service worker entry), guard-rules.js, guard-background.js, signin-guard.js, guard.html, guard.js (sign-in guard)
Extension/testsite/signin-guard: serve.py, index.html, normal-login.html, fake-login.html, fake-brand.html, oauth-links.html (guard test pages)
