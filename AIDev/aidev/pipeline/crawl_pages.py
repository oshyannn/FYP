"""
Collect page content for the content model: phishing pages from the feeds, benign pages from Tranco + your history.

    python feeds.py                        # first: fresh phishing URLs (OpenPhish/URLhaus) and the Tranco list
    python import_phishtank.py             # optional: more verified phishing URLs (needs PHISHTANK_API_KEY)
    python export_history.py               # optional: your own browsing as benign pages
    python crawl_pages.py --phish 3000 --benign 3000
    python train_content.py

RUN IT SOON AFTER REFRESHING THE FEEDS: phishing pages are taken down within hours or days, and dead pages are skipped.
Resumable: run it again with a bigger --phish/--benign to add more; pages already collected are not fetched again.

Safety: pages are downloaded as TEXT only (no JavaScript runs, no files are executed or opened). Phishing sites will see
your IP address; use a network you are comfortable with. Never open the saved .html.gz files in a browser.

Output (data/pages/): pages.csv (one row per page) and html/<id>.html.gz (the HTML, so features can be recomputed
after a feature change without crawling again).

Sampling choices that keep the model honest:
  * only pages that actually loaded (HTTP 200, real HTML); parked / suspended / default-server / 404-style pages are dropped
  * at most 2 pages per registered domain per class; shared hosting platforms are skipped (the content model is not
    used on them, see detector.py)
  * benign pages come from BOTH the top sites and the long tail (ranks 5k-300k, closer to the small sites you really
    visit), and about a third are login pages, so "has a password field" is not a phishing giveaway by itself
"""
from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import random
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from urllib.parse import urlsplit

import pandas as pd

import pagefetch
from common import DATA, PAGES, is_shared, lines
from features import registered_domain

COLUMNS = ["url", "label", "source", "group", "final_url", "status", "tls_invalid", "redirects", "html_file", "fetched_at"]
DEAD = re.compile(
    r"account (has been|is) suspended|has been suspended|site can.?t be reached|domain (is )?for sale|buy this domain|"
    r"404 not found|page not found|index of /|default page|welcome to nginx|apache2? .{0,20}default|coming soon|"
    r"under construction|website is expired|has been removed|suspected phishing|reported as (unsafe|phishing)|"
    r"deceptive site|this domain (is|has)|parked|403 forbidden|access denied|just a moment|checking your browser", re.I)
LOGIN_PATHS = ("/login", "/signin", "/account/login", "/users/sign_in", "/user/login")


def _plain_text(html: str) -> str:
    html = re.sub(r"(?is)<(script|style).*?</\1>", " ", html)
    return " ".join(re.sub(r"(?s)<[^>]+>", " ", html).split())


def usable(page: pagefetch.Page) -> bool:
    if not page.ok or len(page.html) < 300:
        return False
    text = _plain_text(page.html)
    has_form = "<input" in page.html.lower() or "<form" in page.html.lower()
    if len(text) < 40 and not has_form:
        return False
    return not DEAD.search(text[:1500] + " " + (re.search(r"(?is)<title>(.*?)</title>", page.html) or [None, ""])[1])


def _row_for(url: str, label: int, source: str, page: pagefetch.Page) -> dict:
    fid = hashlib.sha1(url.encode()).hexdigest()[:16]
    (PAGES / "html").mkdir(parents=True, exist_ok=True)
    with gzip.open(PAGES / "html" / f"{fid}.html.gz", "wt", encoding="utf-8", errors="replace") as f:
        f.write(page.html[:400_000])
    return {"url": url, "label": label, "source": source, "group": registered_domain(page.url), "final_url": page.url,
            "status": page.status, "tls_invalid": int(page.tls_invalid), "redirects": "|".join(page.redirects),
            "html_file": f"{fid}.html.gz", "fetched_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}


def _candidates(n_benign: int, rng: random.Random) -> list[tuple[str, str]]:
    """(url, source) pairs for benign pages, already shuffled; many more than needed because many fail."""
    out: list[tuple[str, str]] = []
    tranco = lines(DATA / "tranco_top.txt")
    top, tail = tranco[:5000], tranco[5000:300000]
    for _ in range(n_benign * 4):
        pool, src = (top, "benign_top") if rng.random() < 0.4 else (tail, "benign_tail")
        if not pool:
            continue
        dom = rng.choice(pool)
        if is_shared(dom):
            continue
        if rng.random() < 0.35:
            out.append((f"https://{dom}{rng.choice(LOGIN_PATHS)}", src + "_login"))
        else:
            out.append((f"https://{dom}/", src))
    hist = DATA / "benign_extra.csv"
    if hist.exists():
        for u in pd.read_csv(hist)["url"].dropna().astype(str):
            out.append((u, "benign_history"))
    rng.shuffle(out)
    return out


def _phish_candidates(rng: random.Random) -> list[tuple[str, str]]:
    urls = set(lines(DATA / "feeds_urls.txt"))
    extra = DATA / "phishing_extra.csv"
    if extra.exists():
        urls |= {str(u).strip().lower() for u in pd.read_csv(extra)["url"].dropna()}
    out = [(u, "phish_feed") for u in urls if u.startswith("http")]
    rng.shuffle(out)
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--phish", type=int, default=3000, help="target number of usable phishing pages")
    ap.add_argument("--benign", type=int, default=3000, help="target number of usable benign pages")
    ap.add_argument("--workers", type=int, default=24)
    ap.add_argument("--seed", type=int, default=7)
    a = ap.parse_args()

    PAGES.mkdir(parents=True, exist_ok=True)
    csv_path = PAGES / "pages.csv"
    done = pd.read_csv(csv_path) if csv_path.exists() else pd.DataFrame(columns=COLUMNS)
    seen_urls = set(done["url"])
    per_domain: dict[tuple[int, str], int] = {}
    have = {0: 0, 1: 0}
    for lab, grp in zip(done["label"], done["group"]):
        per_domain[(int(lab), grp)] = per_domain.get((int(lab), grp), 0) + 1
        have[int(lab)] += 1
    print(f"already collected: {have[1]} phishing, {have[0]} benign")

    rng = random.Random(a.seed)
    jobs = [(u, 1, s) for u, s in _phish_candidates(rng) if u not in seen_urls][: a.phish * 8]
    jobs += [(u, 0, s) for u, s in _candidates(a.benign, rng) if u not in seen_urls]
    # interleave so both classes are collected at the same time (same crawl period, same network conditions)
    jobs_p = [j for j in jobs if j[1] == 1]
    jobs_b = [j for j in jobs if j[1] == 0]
    mixed = [x for pair in zip(jobs_p, jobs_b) for x in pair] + jobs_p[len(jobs_b):] + jobs_b[len(jobs_p):]

    new_file = not csv_path.exists()
    lock = threading.Lock()
    fh = open(csv_path, "a", newline="", encoding="utf-8")
    writer = csv.DictWriter(fh, fieldnames=COLUMNS)
    if new_file:
        writer.writeheader()
    target = {1: a.phish, 0: a.benign}
    stats = {"tried": 0, "dead": 0, "skipped": 0, "kept": 0}
    t0 = time.time()

    def work(job):
        url, label, source = job
        with lock:
            if have[label] >= target[label]:
                return
        if label == 1 and is_shared(urlsplit(url).hostname or ""):
            with lock:
                stats["skipped"] += 1
            return
        page = pagefetch.fetch(url)
        with lock:
            stats["tried"] += 1
            if not usable(page):
                stats["dead"] += 1
                return
            grp = registered_domain(page.url)
            if is_shared(urlsplit(page.url).hostname or "") or per_domain.get((label, grp), 0) >= 2 or have[label] >= target[label]:
                stats["skipped"] += 1
                return
            per_domain[(label, grp)] = per_domain.get((label, grp), 0) + 1
            have[label] += 1
            stats["kept"] += 1
            writer.writerow(_row_for(url, label, source, page))
            fh.flush()
            if stats["kept"] % 100 == 0:
                print(f"  kept {stats['kept']}  (phishing {have[1]}/{target[1]}, benign {have[0]}/{target[0]})  "
                      f"tried {stats['tried']}  dead/unusable {stats['dead']}  {time.time() - t0:.0f}s")

    with ThreadPoolExecutor(max_workers=a.workers) as ex:
        futs = [ex.submit(work, j) for j in mixed]
        try:
            for _ in as_completed(futs):
                if have[1] >= target[1] and have[0] >= target[0]:
                    break
        except KeyboardInterrupt:
            print("stopped; what was collected is saved, run again to continue")
            for f in futs:
                f.cancel()
    fh.close()
    print(f"done: {have[1]} phishing, {have[0]} benign pages in {csv_path}  (tried {stats['tried']}, dead/unusable {stats['dead']})")
    if have[1] < 300:
        print("Too few phishing pages for a useful model. Most feed URLs were already dead: refresh the feeds and run again immediately.")


if __name__ == "__main__":
    main()
