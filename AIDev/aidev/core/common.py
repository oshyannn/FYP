"""Shared paths and small helpers. Run AIDev commands from the AIDev/ folder:  python -m aidev.<folder>.<module>"""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]       # = the AIDev/ folder; everything below lives next to the aidev/ package
BASE = ROOT                                      # old name, kept so older code keeps working
DATA = ROOT / "data"                             # downloaded feeds, datasets, crawled pages (NOT in git, see data/README.md)
LISTS = ROOT / "lists"                           # hand-edited whitelist / blacklist ... (in git)
MODELS = ROOT / "models"                         # trained models (*.joblib NOT in git) + their metrics json (in git)
EXPERIMENTS = ROOT / "experiments"               # side models from `train_content --out NAME` (*.joblib NOT in git)
MODEL_PATH = MODELS / "model.joblib"
METRICS_PATH = MODELS / "model_metrics.json"
CONTENT_MODEL_PATH = MODELS / "model_content.joblib"
CONTENT_METRICS_PATH = MODELS / "model_content_metrics.json"
PAGES = DATA / "pages"


def _load_env() -> None:
    """Read KEY=VALUE lines from AIDev/.env into os.environ (real environment variables win)."""
    import os
    f = BASE / ".env"
    if not f.exists():
        return
    for raw in f.read_text(encoding="utf-8", errors="ignore").splitlines():
        raw = raw.strip()
        if not raw or raw.startswith("#") or "=" not in raw:
            continue
        k, v = raw.split("=", 1)
        k, v = k.strip(), v.strip().strip('"').strip("'")
        if k and v:
            os.environ.setdefault(k, v)


_load_env()


def lines(path: Path) -> list[str]:
    """Read a text list: strip blanks and '#' comments, lowercase. Missing file -> []."""
    if not path.exists():
        return []
    out = []
    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        s = raw.strip().lower()
        if s and not s.startswith("#"):
            out.append(s)
    return out


_SHARED: set[str] | None = None


def is_shared(host: str) -> bool:
    """True if host is (a subdomain of) a shared hosting platform listed in lists/shared_hosts.txt."""
    global _SHARED
    if _SHARED is None:
        _SHARED = set(lines(LISTS / "shared_hosts.txt"))
    host = host.lower().split(":")[0]
    return any(host == s or host.endswith("." + s) for s in _SHARED)
