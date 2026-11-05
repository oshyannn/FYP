# Optional AI check for URLs on a list — install

Extract this zip INTO your FYP folder (merge folders). Delete this file afterwards.
Tell your ML collaborator first: it touches AIDev/aidev/detection/detector.py (the list path only; results change only when the box is ticked).

## New file
Backend/scripts/enable_optional_ai.py     one-time: edits detector.py and scans.py together (all or nothing)

## 1 file that is replaced (differences are marked "added" / "changed")
DesktopApp/src/pages/user/scan/UrlScanner.tsx     checkbox "Also run the AI models, even if this address is already on a blacklist or whitelist"
If you changed this file locally since the last commit, compare before overwriting.

## Steps
1. cd Backend ; python -m scripts.enable_optional_ai
   - changes AIDev/aidev/detection/detector.py and Backend/web/controllers/scans.py, or neither (if a place was edited it says which)
   - backups: detector.py.before_optional_ai.bak and scans.py.before_optional_ai.bak
   - safe to run twice
2. Restart: python app.py     then the desktop app: npm run dev
3. URL Scanner -> tick the box -> scan a blacklisted or whitelisted address -> open Detailed Analysis.

## Behaviour
- Box NOT ticked: exactly as before (a list hit is answered at once, AI 1 / AI 2 show "Not run").
- Box ticked and the URL is on a list (blacklist, OpenPhish/URLhaus feed, adult list, whitelist, Tranco top list,
  institutional endings, trusted paths): AI 1 and AI 2 also run and appear in the detail screen.
  THE LIST STILL DECIDES the final status. Notes say when the AI disagrees:
    trusted site + AI sees warning signs  -> "The AI models disagree with the trusted list ..."
    blocked site + AI sees nothing        -> "The AI models see no strong warning sign, but the list result stays."
- URLs no list knows are always analysed with the AI models (the box changes nothing for them).
- If the AI step fails, the scan still returns the normal list result.
- The result carries ai_optional: true, so screens can tell. Only the desktop URL Scanner has the box:
  the Dashboard quick-scan and the Chrome extension do not send it (they behave as before).
- Your own Supabase whitelist (user / administrator) is applied after the detector and is not a "list" here: those
  URLs already go through the AI models.

## Undo
Copy the two .before_optional_ai.bak files back over detector.py and scans.py, and restore the old UrlScanner.tsx.
If you later run the age-rule fix's "upgrade" (it restores detector.py from detector.py.bak), run this script again.

## file_structure.md — add this
Backend/scripts: enable_optional_ai.py (one-time: lets POST /api/scans take "use_ai"; edits detector.py + scans.py)
Section "Scanning": POST /api/scans accepts {"url", "use_ai"}; use_ai=true runs AI 1 + AI 2 on list-decided URLs (list result still final)
