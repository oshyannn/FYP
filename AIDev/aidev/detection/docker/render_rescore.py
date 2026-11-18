"""Stage 2: re-score uncertain pages from a sandboxed render (Docker). OFF unless RENDER_CHECK=1. Never raises."""
from __future__ import annotations

import json
import logging
import os
import subprocess
from pathlib import Path

import joblib

from aidev.core.common import CONTENT_MODEL_PATH
from aidev.detection import content_features as cf

log = logging.getLogger(__name__)

IMAGE = "fyp-render"
TIMEOUT_S = 90
RENDER_MODEL_PATH = Path(CONTENT_MODEL_PATH).with_name("model_content_render.joblib")
_bundle = {"loaded": False, "value": None}


def enabled() -> bool:
    return os.environ.get("RENDER_CHECK") == "1"


def _load():
    if not _bundle["loaded"]:
        _bundle["loaded"] = True
        try:
            if RENDER_MODEL_PATH.exists():
                _bundle["value"] = joblib.load(RENDER_MODEL_PATH)
        except Exception as exc:
            log.warning("render model load failed: %s", exc)
    return _bundle["value"]


def _run_container(url: str) -> dict:
    cmd = ["docker", "run", "--rm", "--network", "bridge", "--read-only",
           "--tmpfs", "/tmp", "--tmpfs", "/home/renderer",
           "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
           "--memory", "2g", "--cpus", "2", "--pids-limit", "300",
           "--entrypoint", "python", IMAGE, "/app/render_one.py", url]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT_S)
    lines = [ln for ln in proc.stdout.splitlines() if ln.strip()]
    if not lines:
        raise RuntimeError("no output from container: " + proc.stderr[-200:])
    return json.loads(lines[-1])


def rescore(url: str, static_res: dict) -> dict:
    out = {"render_used": False, "render_status": "off", "probability_rendered": None,
           "probability_rendered_calibrated": None, "flagged_rendered": None, "rendered_final_url": None}
    if not enabled():
        return out
    try:
        return _rescore(url, static_res, out)
    except Exception as exc:                      # a failed render never means "safe"; keep the static result
        log.warning("render rescore failed: %s", exc)
        out["render_used"] = False
        out["render_status"] = "error"
        return out


def _rescore(url: str, static_res: dict, out: dict) -> dict:
    p_static = static_res.get("probability_calibrated")
    if p_static is None:
        out["render_status"] = "no_static_score"
        return out
    bundle = _load()
    if bundle is None:
        out["render_status"] = "no_model"
        return out
    low, high = bundle["render_band"]
    if not (low <= p_static <= high):
        out["render_status"] = "outside_band"
        return out
    if not url.lower().startswith(("http://", "https://")):
        out["render_status"] = "bad_scheme"
        return out
    r = _run_container(url)
    if not r.get("ok") or not r.get("html"):
        out["render_status"] = "render_failed:%s" % (r.get("status") or r.get("error") or "unknown")
        return out
    final_url = r.get("final_url") or url
    f = cf.extract(r["html"], final_url, r.get("redirects") or [], False)
    x = [[f[n] for n in bundle["feature_names"]]]
    p = float(bundle["model"].predict_proba(x)[0][1])
    p_cal = float(bundle["calibrator"].predict([p])[0])
    out.update({"render_used": True, "render_status": "ok", "probability_rendered": p,
                "probability_rendered_calibrated": p_cal, "rendered_final_url": final_url,
                "flagged_rendered": p_cal >= bundle["threshold"]})
    return out