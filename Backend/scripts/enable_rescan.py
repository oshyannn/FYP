"""Re-scan support: POST /api/scans accepts {"url": "...", "fresh": true} (safe to run more than once).

Run from the Backend folder:   python -m scripts.enable_rescan

The detector remembers answers so one page is not looked up again and again: a finished verdict (5 minutes when a source could not
answer, up to 1 hour or 6 hours otherwise), the PhishTank answer and the Google Safe Browsing answer (1 hour). With "fresh": true the
detector first forgets what it remembers about that ONE address, so the new scan asks every source again. Without it nothing changes.

It edits two files and either changes both or none (backups: *.before_rescan.bak):
  AIDev/aidev/detection/detector.py     adds the function forget(url) at the end of the file
  Backend/web/controllers/scans.py      imports forget, and calls it when the request says "fresh"
It works whether or not the "optional AI" patch (enable_optional_ai) was applied before.
"""
from __future__ import annotations

import re
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DETECTOR = ROOT / "AIDev" / "aidev" / "detection" / "detector.py"
SCANS = ROOT / "Backend" / "web" / "controllers" / "scans.py"

FORGET = '''

def forget(raw_url: str) -> None:
    """Drop what is remembered about ONE address (the finished verdict, the PhishTank answer and the Safe Browsing answer), so the
    next analyze() asks every source again. Used by "Re-scan"; it changes nothing about how a verdict is made."""
    url = normalize(raw_url)
    _result_cache.pop(url, None)
    _cache.pop(url, None)
    _sb_cache.pop(url, None)
'''
IMPORT_OLD = "from aidev.detection.detector import analyze\n"
IMPORT_NEW = "from aidev.detection.detector import analyze, forget\n"
CALL = re.compile(r"^(?P<ind>[ \t]+)result = analyze\(url[^\n]*\n", re.M)


def main() -> int:
    for path in (DETECTOR, SCANS):
        if not path.exists():
            print(f"Cannot find {path}")
            return 1
    det = DETECTOR.read_text(encoding="utf-8")
    scn = SCANS.read_text(encoding="utf-8")
    plan = []
    if "def forget(" in det:
        print("detector.py: already changed.")
    else:
        for name in ("\n_result_cache:", "\n_cache:", "\n_sb_cache:", "import normalize"):
            if name not in det:
                print(f"Nothing was changed. detector.py has no '{name.strip()}' (a cache or the normalize import this script needs), so it "
                      "differs from what the script expects. Send me the file.")
                return 1
        plan.append((DETECTOR, det.rstrip("\n") + "\n" + FORGET))
    if "forget(url)" in scn:
        print("scans.py: already changed.")
    else:
        if scn.count(IMPORT_OLD) != 1 or len(CALL.findall(scn)) != 1:
            print("Nothing was changed. scans.py was edited where this script needs to change it (the 'import analyze' line or the "
                  "'result = analyze(url...)' line was not found exactly once). Send me the file.")
            return 1
        scn = scn.replace(IMPORT_OLD, IMPORT_NEW)
        mm = CALL.search(scn)
        ind = mm.group("ind")
        insert = (f"{ind}if data.get(\"fresh\") is True:                     # \"Re-scan\": forget the remembered answers for this address first\n"
                  f"{ind}    forget(url)\n")
        scn = scn[:mm.start()] + insert + scn[mm.start():]
        plan.append((SCANS, scn))
    if not plan:
        print("Nothing to do.")
        return 0
    for path, text in plan:
        shutil.copyfile(path, path.with_name(path.name + ".before_rescan.bak"))
        path.write_text(text, encoding="utf-8")
        print(f"Changed {path.name} (backup: {path.name}.before_rescan.bak)")
    print("Restart the backend: python app.py")
    return 0


if __name__ == "__main__":
    sys.exit(main())
