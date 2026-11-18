"""
One table from several saved experiments (own code, standard library only).

    python -m aidev.evaluation.summarize_runs m2_v3 own_w3 own_w6 --out experiments/summary.md
    python -m aidev.evaluation.summarize_runs "own_w3_s*" --mean      # runs that differ only by --seed: mean and spread

Reads experiments/NAME.json written by train_content2. Columns (raw probability): PR-AUC, ROC-AUC, recall at 1% false-positive
rate, accuracy at probability 0.5 and its false-positive rate; (calibrated, threshold fixed on validation): recall and
false-positive rate the threshold really gives on the test pages.
"""
from __future__ import annotations

import argparse
import glob
import json
import math
from pathlib import Path

from aidev.core.common import EXPERIMENTS

COLUMNS = [("pr_auc", "raw", "PR-AUC"), ("roc_auc", "raw", "ROC-AUC"), ("recall@fpr1%", "raw", "recall @1% FPR"),
           ("t0.5_accuracy", "raw", "accuracy @0.5"), ("t0.5_fpr", "raw", "FPR @0.5"),
           ("fixed_recall", "cal", "recall @val. threshold"), ("fixed_fpr", "cal", "FPR @val. threshold")]


def load_run(path: Path) -> dict:
    r = json.loads(path.read_text(encoding="utf-8"))
    out = {"name": path.stem, "mode": r.get("eval_mode", "")}
    for key, which, _ in COLUMNS:
        out[key] = r["test_raw" if which == "raw" else "test_calibrated"]["point"].get(key, math.nan)
    return out


def mean_sd(vals: list[float]) -> tuple[float, float]:
    v = [x for x in vals if not math.isnan(x)]
    if not v:
        return math.nan, math.nan
    m = sum(v) / len(v)
    return m, (math.sqrt(sum((x - m) ** 2 for x in v) / (len(v) - 1)) if len(v) > 1 else 0.0)


def table(runs: list[dict], mean: bool = False) -> str:
    head = "| run | mode | " + " | ".join(c[2] for c in COLUMNS) + " |"
    L = [head, "|" + "---|" * (len(COLUMNS) + 2)]
    if mean and runs:
        cells = []
        for key, _, _ in COLUMNS:
            m, sd = mean_sd([r[key] for r in runs])
            cells.append(f"{m:.3f} +- {sd:.3f}")
        L.append(f"| mean of {len(runs)} runs | {runs[0]['mode']} | " + " | ".join(cells) + " |")
    else:
        for r in runs:
            L.append(f"| {r['name']} | {r['mode']} | " + " | ".join(f"{r[k]:.3f}" for k, _, _ in COLUMNS) + " |")
    return "\n".join(L)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("names", nargs="+", help="experiment names or glob patterns (without .json)")
    ap.add_argument("--mean", action="store_true", help="average all matched runs into one row (use for different seeds)")
    ap.add_argument("--out", default="")
    a = ap.parse_args()
    files = []
    for n in a.names:
        files += sorted(glob.glob(str(EXPERIMENTS / f"{n}.json")))
    if not files:
        raise SystemExit("no experiment files matched")
    md = table([load_run(Path(f)) for f in files], a.mean)
    print(md)
    if a.out:
        Path(a.out).write_text(md + "\n", encoding="utf-8")
