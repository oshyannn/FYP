"""check_structure.py: compare file_structure.md with the real repo (stdlib only).

Put this in the FYP root (next to file_structure.md) and run:

    python check_structure.py          # report: new files not in the md, md paths that no longer exist
    python check_structure.py --tree   # also print a full tree of git-visible files (paste into the md)

It sees tracked files AND new uncommitted files, but never anything in .gitignore
(.venv, node_modules, .joblib, data/ ...). It does not edit the md; you add the
one-line descriptions yourself (or ask Claude to).
"""
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DOC = ROOT / "file_structure.md"

# Files that do not need a line in the md (edit to taste)
SKIP_SUFFIX = {".png", ".jpg", ".jpeg", ".svg", ".ico", ".gif", ".woff", ".woff2", ".lock"}
SKIP_NAMES = {"package-lock.json", ".gitignore", ".gitkeep"}
SKIP_PREFIX = ("Extension/chrome/icons/", "Extension/chrome/popup/", "AIDev/docs/archive/")


def git_files():
    out = subprocess.run(
        ["git", "-c", "core.quotepath=false", "ls-files", "--cached", "--others", "--exclude-standard"],
        cwd=ROOT, capture_output=True, text=True, encoding="utf-8", check=True,
    ).stdout
    return sorted({f for f in out.splitlines() if (ROOT / f).exists()})


def needs_entry(f):
    p = Path(f)
    return not (p.suffix.lower() in SKIP_SUFFIX or p.name in SKIP_NAMES or f.startswith(SKIP_PREFIX))


def print_tree(files):
    tree = {}
    for f in files:
        node = tree
        for part in f.split("/"):
            node = node.setdefault(part, {})

    def walk(node, indent=""):
        items = sorted(node.items(), key=lambda kv: (not kv[1], kv[0].lower()))
        for i, (name, child) in enumerate(items):
            last = i == len(items) - 1
            print(f"{indent}{'└── ' if last else '├── '}{name}{'/' if child else ''}")
            if child:
                walk(child, indent + ("    " if last else "│   "))

    print("FYP/")
    walk(tree)


def main():
    if not DOC.exists():
        sys.exit("file_structure.md not found next to this script")
    text = DOC.read_text(encoding="utf-8")
    files = git_files()

    # 1) real files the md never mentions (heuristic: file name or name without extension appears in the md)
    missing = [f for f in files if needs_entry(f)
               and Path(f).name not in text and Path(f).stem not in text]
    print("== Files that exist but are NOT mentioned in file_structure.md ==")
    print("\n".join(f"  {f}" for f in missing) or "  (none)")

    # 2) paths in `backticks` that no longer exist
    stale = []
    for tok in sorted(set(re.findall(r"`([^`\s]+)`", text))):
        t = tok.lstrip("./")
        if not re.search(r"\.\w{1,5}$", t) or any(c in t for c in "*<>{}|="):
            continue
        if not ((ROOT / t).exists() or any(f == t or f.endswith("/" + t) for f in files)):
            stale.append(tok)
    print("\n== Names in the md that were not found among git-visible files ==")
    print("   (can be fine: .env, .joblib, data/ are not in git)")
    print("\n".join(f"  {s}" for s in stale) or "  (none)")

    if "--tree" in sys.argv:
        print("\n== Tree of git-visible files ==")
        print_tree(files)


if __name__ == "__main__":
    main()
