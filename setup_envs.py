#!/usr/bin/env python3
"""
Create one virtual environment per Python folder and install what each needs. Uses only the standard library.

    python setup_envs.py                   # AIDev + Backend venvs, npm install for DesktopApp and Extension/ui
    python setup_envs.py --dry-run         # only print what would happen
    python setup_envs.py --only aidev      # one part: aidev | backend | desktop | ui  (can be repeated)

Run it with any Python 3.11+ (3.13 recommended: that is what the pinned versions were tested with). The venvs are created
from the Python that runs this script, so if `python` is not on your PATH use the full path to python.exe.
Safe to run again: existing venvs are reused, pip only installs what is missing.
"""
import argparse
import os
import shutil
import subprocess
import sys
import venv
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PY_PARTS = {"aidev": ROOT / "AIDev", "backend": ROOT / "Backend"}
NODE_PARTS = {"desktop": ROOT / "DesktopApp", "ui": ROOT / "Extension" / "ui"}
SMOKE = {
    "aidev": "import aidev.core.common as c; import sklearn, joblib, tldextract, requests; print('AIDev ok, ROOT =', c.ROOT)",
    "backend": ("import sys; sys.path.insert(0, '../AIDev'); import flask, flask_limiter, argon2, email_validator, psycopg, "
                "psycopg_pool, dotenv, sklearn, joblib, tldextract; import aidev.core.common as c; print('Backend ok, engine at', c.ROOT)"),
}


def venv_python(folder):
    return folder / ".venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def run(cmd, cwd, dry):
    print("  $", " ".join(str(c) for c in cmd), f"   (in {cwd.name}/)")
    if dry:
        return 0
    return subprocess.run([str(c) for c in cmd], cwd=cwd).returncode


def setup_python(name, folder, dry):
    print(f"\n== {folder.name}: Python venv")
    if not (folder / "requirements.txt").exists():
        print("  requirements.txt not found, skipping")
        return False
    py = venv_python(folder)
    if py.exists():
        print("  venv exists, reusing", py)
    else:
        print("  creating", folder / ".venv", "from", sys.executable)
        if not dry:
            venv.EnvBuilder(with_pip=True).create(folder / ".venv")
    if run([py, "-m", "pip", "install", "-r", "requirements.txt"], folder, dry) != 0:
        print("  !! pip install failed (see messages above)")
        return False
    if run([py, "-c", SMOKE[name]], folder, dry) != 0:
        print("  !! packages installed but the import check failed")
        return False
    if not dry:
        out = subprocess.run([str(py), "-m", "pip", "freeze"], cwd=folder, capture_output=True, text=True).stdout
        (folder / "requirements.lock.txt").write_text(out, encoding="utf-8")
        print("  wrote requirements.lock.txt (exact versions of everything installed; commit it if you like)")
    return True


def setup_node(name, folder, dry):
    print(f"\n== {folder.relative_to(ROOT)}: npm packages")
    if not (folder / "package.json").exists():
        print("  no package.json here yet, skipping" + ("  (run migrate_local.py to copy DesktopApp in)" if name == "desktop" else ""))
        return True
    npm = shutil.which("npm")
    if not npm:
        print("  npm not found. Install Node.js from https://nodejs.org and run this again.")
        return False
    cmd = [npm, "ci" if (folder / "package-lock.json").exists() else "install"]
    return run(cmd, folder, dry) == 0


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--only", action="append", choices=[*PY_PARTS, *NODE_PARTS], help="limit to one part (repeatable)")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    if sys.version_info < (3, 11):
        sys.exit(f"Python {sys.version.split()[0]} is too old; use 3.11 or newer (3.13 recommended).")
    want = set(a.only or [*PY_PARTS, *NODE_PARTS])
    print(f"Using Python {sys.version.split()[0]} at {sys.executable}")
    results = {}
    for n, f in PY_PARTS.items():
        if n in want:
            results[n] = setup_python(n, f, a.dry_run)
    for n, f in NODE_PARTS.items():
        if n in want:
            results[n] = setup_node(n, f, a.dry_run)
    print("\nSummary:", ", ".join(f"{k}: {'ok' if v else 'FAILED'}" for k, v in results.items()))
    sys.exit(0 if all(results.values()) else 1)


if __name__ == "__main__":
    main()
