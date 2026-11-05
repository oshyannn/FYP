"""Why does the URL model not load?     python -m aidev.tools.check_model

Prints the model file, the library versions and the REAL error (full traceback) from joblib.load."""
import importlib.metadata as md
import traceback

from aidev.core.common import MODEL_PATH
from aidev.core.features import FEATURE_NAMES, FEATURE_VERSION

print("model file   :", MODEL_PATH)
print("exists       :", MODEL_PATH.exists())
if MODEL_PATH.exists():
    print("size         : %.1f MB" % (MODEL_PATH.stat().st_size / 1e6))
    with open(MODEL_PATH, "rb") as f:
        head = f.read(16)
    print("first bytes  :", head)

# the project pins these (AIDev/requirements-runtime.txt): the model must be loaded with the versions that trained it
for pkg, want in (("scikit-learn", "1.9.1"), ("joblib", "1.6.0"), ("numpy", "2.5.4"), ("pandas", "3.0.6"), ("tldextract", "5.4.0")):
    try:
        have = md.version(pkg)
    except md.PackageNotFoundError:
        have = "NOT INSTALLED"
    print(f"{pkg:13}: installed {have:14} pinned {want}  {'ok' if have == want else '<-- different'}")

print("\nfeatures.py  : FEATURE_VERSION", FEATURE_VERSION, "|", len(FEATURE_NAMES), "features")
if not MODEL_PATH.exists():
    raise SystemExit("\nThe model file is missing. Create it with: python -m aidev.pipeline.train")

import joblib  # noqa: E402

print("\nloading ...")
try:
    b = joblib.load(MODEL_PATH)
except BaseException:
    print("joblib.load FAILED:\n")
    traceback.print_exc()
    raise SystemExit(1)
print("loaded. keys:", sorted(b) if isinstance(b, dict) else type(b))
if isinstance(b, dict):
    print("model feature_version:", b.get("feature_version"), "| same feature names:", b.get("feature_names") == FEATURE_NAMES)
    print("model version        :", b.get("version"))
