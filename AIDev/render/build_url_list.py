"""Pick a small, reviewable URL list for the first render run. Own-crawled pages only."""
import sys
from pathlib import Path

import pandas as pd

N_EACH = int(sys.argv[1]) if len(sys.argv) > 1 else 25
SEED = 42
SRC = Path("data/pages/pages.csv")
OUT = Path("render_io/in/urls_first.csv")

d = pd.read_csv(SRC)
d = d[d["source"].isin(["phish_feed", "benign_tail", "benign_tail_login", "benign_top", "benign_top_login"])]
d = d[d["url"].str.lower().str.startswith(("http://", "https://"))]
d = d.drop_duplicates("group")                       # at most one page per site

phish = d[d["label"] == 1].sample(n=min(N_EACH, (d["label"] == 1).sum()), random_state=SEED)
benign = d[d["label"] == 0].sample(n=min(N_EACH, (d["label"] == 0).sum()), random_state=SEED)
out = pd.concat([phish, benign])[["url", "label", "source", "group"]]

OUT.parent.mkdir(parents=True, exist_ok=True)
out.to_csv(OUT, index=False)
print(len(out), "rows ->", OUT)
print(out.groupby(["label", "source"]).size())