import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from collections import Counter
from aidev.evaluation.clone_diagnostic import run

res = run("experiments/m2_v3_own_preds.csv", "data/pages/pages.csv", 3000, 600, 42, None)
bg = res["scored"]["benign (background)"]
hi = bg[bg.sim >= 0.99]

print("benign pages with sim >= 0.99:", len(hi))
print("copies (domain) counts:")
for dom, n in Counter(hi["copies"]).most_common(20):
    print(f"  {n:3d}  {dom}")