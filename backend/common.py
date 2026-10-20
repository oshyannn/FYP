"""Shared paths and small helpers. Run everything from backend/."""
from __future__ import annotations

from pathlib import Path

BASE = Path(__file__).resolve().parent
DATA = BASE / "data"
LISTS = BASE / "lists"
MODEL_PATH = BASE / "model.joblib"
METRICS_PATH = BASE / "model_metrics.json"
CONTENT_MODEL_PATH = BASE / "model_content.joblib"
CONTENT_METRICS_PATH = BASE / "model_content_metrics.json"
PAGES = DATA / "pages"


def _load_env() -> None:
    """Read KEY=VALUE lines from backend/.env into os.environ (real environment variables win)."""
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
