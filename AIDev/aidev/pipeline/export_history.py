"""
Export YOUR OWN Chrome browsing history as benign training URLs -> data/benign_extra.csv.

    python -m aidev.pipeline.export_history

Runs entirely on your computer; nothing is uploaded. Privacy measures:
  * query strings and #fragments are removed (tokens/search terms live there);
  * only http(s) URLs; localhost, private IPs and dotless hosts are skipped;
  * at most MAX_PER_DOMAIN URLs per domain.
Paths can still contain private names. Keep data/ out of git and never share the file.
Assumption: the sites you normally visit are legitimate. Delete any you do not trust.
"""
from __future__ import annotations

import os
import shutil
import sqlite3
import sys
import tempfile
from collections import Counter
from urllib.parse import urlsplit

import pandas as pd

from aidev.core.common import DATA
from aidev.core.features import registered_domain

MAX_PER_DOMAIN = 10


def history_path() -> str:
    if len(sys.argv) > 1:
        return sys.argv[1]
    local = os.environ.get("LOCALAPPDATA", "")
    return os.path.join(local, "Google", "Chrome", "User Data", "Default", "History")


def main() -> None:
    src = history_path()
    if not os.path.exists(src):
        raise SystemExit(f"History file not found: {src}\n"
                         "Pass the path as an argument (Chrome profiles: 'Default', 'Profile 1', ...).")
    tmp = os.path.join(tempfile.mkdtemp(), "History")
    shutil.copy2(src, tmp)                       # Chrome locks the original while running
    con = sqlite3.connect(tmp)
    rows = [r[0] for r in con.execute("SELECT url FROM urls")]
    con.close()

    seen, per_domain, out = set(), Counter(), []
    for u in rows:
        p = urlsplit(u)
        host = (p.hostname or "").lower()
        if p.scheme not in ("http", "https") or "." not in host:
            continue
        if host == "localhost" or host.startswith(("192.168.", "10.", "127.")):
            continue
        clean = f"{p.scheme}://{p.netloc}{p.path}"
        if clean in seen:
            continue
        try:
            dom = registered_domain(clean)
        except Exception:
            continue
        if per_domain[dom] >= MAX_PER_DOMAIN:
            continue
        per_domain[dom] += 1
        seen.add(clean)
        out.append(clean)

    DATA.mkdir(exist_ok=True)
    pd.DataFrame({"url": out}).to_csv(DATA / "benign_extra.csv", index=False)
    print(f"benign_extra.csv: {len(out)} URLs from {len(per_domain)} domains")


if __name__ == "__main__":
    main()
