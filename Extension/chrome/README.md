# SafeBrowse browser extension

Load it: `chrome://extensions` → Developer mode → **Load unpacked** → select this `extension/` folder.

## Sign-in = pairing with the desktop app
There is no login form here. Open the desktop app → **Generate pairing code** → type the code in the extension popup.
The extension calls `POST /api/extension/pair`, stores its own token in `chrome.storage.local` and sends it as
`Authorization: Bearer …` on every `/analyze` call. If the token is revoked (desktop app → disconnect, password reset) the
next call returns 401, the badge shows `!` and the popup asks for a new code.

## Popup (React, from the Figma export)
Source: `../extension-ui/`. Rebuild after changing it:

    cd extension-ui && npm install && npm run build    # writes extension/popup/

The built `extension/popup/` is committed so the extension works without a build step.

## Where data lives (Supabase hook-up points)
- Settings / history / auth → `chrome.storage.local`, read and written only through `extension-ui/src/store.ts`
  (popup) and `recordHistory()` / `getSettings()` in `background.js`. Replace those to sync with Supabase.
- Backend URL → `API_BASE` in `background.js` and `extension-ui/src/config.ts` (keep both in sync).

## Pages
`blocked.html`, `checking.html`, `prompt.html` share `pages/ui.css` (same palette as the popup). Their logic is unchanged
apart from the two-step "Continue" on the blocked page.
