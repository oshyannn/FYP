"""Shared paths and small helpers. Run everything from backend/."""
from __future__ import annotations

from pathlib import Path

BASE = Path(__file__).resolve().parent
DATA = BASE / "data"
LISTS = BASE / "lists"
MODEL_PATH = BASE / "model.joblib"
METRICS_PATH = BASE / "model_metrics.json"


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
