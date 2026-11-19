"""Isolated Docker/Playwright dynamic scan orchestrator & AI 2 rendered-DOM evaluator."""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import urlsplit

from web.db_models import dynamic_scans

log = logging.getLogger(__name__)

IMAGE_NAME = os.getenv("DYNAMIC_SCANNER_IMAGE", "safebrowse-scanner:latest")
CONTAINER_TIMEOUT_S = int(os.getenv("DYNAMIC_SCANNER_TIMEOUT_S", "55"))
NAV_TIMEOUT_MS = int(os.getenv("SCAN_NAV_TIMEOUT_MS", "25000"))
POST_LOAD_MS = int(os.getenv("SCAN_POST_LOAD_MS", "3000"))
TOTAL_BUDGET_S = float(os.getenv("SCAN_TOTAL_BUDGET_S", "40.0"))
MAX_GLOBAL_WORKERS = int(os.getenv("DYNAMIC_SCANNER_CONCURRENCY", "2"))
MAX_USER_ACTIVE = 2
MAX_STDOUT_BYTES = 2 * 1024 * 1024
ALLOWED_STATUSES = {"completed", "partial", "failed", "timed_out"}

_EXECUTOR = ThreadPoolExecutor(max_workers=MAX_GLOBAL_WORKERS, thread_name_prefix="dyn-scan")


def is_public_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str.split("%")[0])
        return ip.is_global and not (
            ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified
        )
    except ValueError:
        return False


_NON_HTTP_SCHEME_RE = re.compile(r"^(javascript|data|file|mailto|tel|blob|about|vbscript):", re.IGNORECASE)


def normalize_scan_url(raw_url: str) -> tuple[str, bool]:
    """Prepends https:// when no scheme is provided. Returns (url, defaulted_https)."""
    cleaned = (raw_url or "").strip()
    if cleaned and "://" not in cleaned and not _NON_HTTP_SCHEME_RE.match(cleaned):
        return f"https://{cleaned}", True
    return cleaned, False


def validate_public_url(raw_url: str, allow_private: bool = False) -> tuple[bool, str]:
    normalized, _ = normalize_scan_url(raw_url)
    try:
        parts = urlsplit(normalized)
    except ValueError:
        return False, "Invalid URL."
    if parts.scheme.lower() not in ("http", "https"):
        return False, "Only http and https URLs are supported."
    host = (parts.hostname or "").strip().lower().rstrip(".")
    if not host:
        return False, "Missing hostname."
    if allow_private:
        return True, ""
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return False, "Domain could not be resolved."
    addrs = {i[4][0] for i in infos}
    if not addrs or not all(is_public_ip(a) for a in addrs):
        return False, "Blocked non-public or internal network address."
    return True, ""


def _evaluate_ai2_on_rendered_dom(rendered_html: str, final_url: str, redirects: list[str]) -> dict | None:
    """Runs the existing AI 2 38-feature contract on the browser-rendered DOM without modifying the model."""
    if not rendered_html or len(rendered_html) < 200:
        return None
    try:
        aidev_dir = str(Path(__file__).resolve().parents[3] / "AIDev")
        if aidev_dir not in sys.path:
            sys.path.insert(0, aidev_dir)
        from aidev.detection import content_features as cf
        from aidev.detection import page_threats, predict_content

        bundle = predict_content._load()
        if bundle is None:
            return None
        feats = cf.extract(rendered_html, final_url, redirects, False)
        p = float(bundle["model"].predict_proba([[feats[n] for n in bundle["feature_names"]]])[0][1])
        p_cal = None
        thr = None
        flagged = None
        if bundle.get("calibrator") is not None:
            p_cal = float(bundle["calibrator"].predict([p])[0])
            thr = predict_content._threshold(bundle)
            flagged = (p_cal + 1e-6 >= thr) if thr is not None else None
        score_ref = p_cal if p_cal is not None else p
        risk_tier = "flagged" if flagged else ("suspicious" if score_ref >= 0.5 else "low")
        sigs = predict_content.signals(feats)
        cats = page_threats.assess(feats, None)
        return {
            "model_version": bundle.get("version"),
            "probability": round(p, 4),
            "percent": round(p * 100, 1),
            "probability_calibrated": round(p_cal, 4) if p_cal is not None else None,
            "calibrated_percent": round(p_cal * 100, 1) if p_cal is not None else None,
            "threshold": round(float(thr), 4) if thr is not None else None,
            "flagged": flagged,
            "risk_tier": risk_tier,
            "signals": sigs[:10],
            "categories": cats,
            "note": "AI 2 evaluated on browser-rendered DOM (post-JavaScript execution).",
        }
    except Exception as exc:
        log.warning("AI 2 dynamic DOM evaluation failed: %s", exc)
        return None


def _normalize_evidence(raw: dict) -> tuple[dict, str, list[str]]:
    """Validates worker JSON and strips raw HTML before DB persistence."""
    dom = raw.get("dom") if isinstance(raw.get("dom"), dict) else {}
    rendered_html = dom.get("rendered_html") if isinstance(dom.get("rendered_html"), str) else ""
    nav = raw.get("navigation") if isinstance(raw.get("navigation"), dict) else {}
    redirects = [str(u)[:1024] for u in (nav.get("redirect_urls") or [])[:10]]
    net = raw.get("network") if isinstance(raw.get("network"), dict) else {}
    scripts = raw.get("scripts") if isinstance(raw.get("scripts"), dict) else {}
    beh = raw.get("behaviour") if isinstance(raw.get("behaviour"), dict) else {}
    lims = [str(x)[:300] for x in (raw.get("limitations") or [])[:10]]

    evidence = {
        "schema_version": 1,
        "requested_url": str(raw.get("requested_url") or "")[:2048],
        "final_url": str(raw.get("final_url") or "")[:2048],
        "navigation": {
            "redirect_count": int(nav.get("redirect_count") or 0),
            "redirect_urls": redirects,
            "http_status": nav.get("http_status"),
        },
        "network": {
            "request_count": int(net.get("request_count") or 0),
            "external_domains": [str(d)[:253] for d in (net.get("external_domains") or [])[:50]],
            "failed_request_count": int(net.get("failed_request_count") or 0),
            "blocked_ssrf_count": int(net.get("blocked_ssrf_count") or 0),
        },
        "scripts": {
            "external_script_count": int(scripts.get("external_script_count") or 0),
            "inline_script_count": int(scripts.get("inline_script_count") or 0),
            "script_urls": [str(u)[:512] for u in (scripts.get("script_urls") or [])[:50]],
        },
        "dom": {
            "snapshot_captured": bool(dom.get("snapshot_captured")),
            "rendered_html_bytes": len(rendered_html.encode("utf-8", errors="ignore")),
            "form_count": int(dom.get("form_count") or 0),
            "password_field_count": int(dom.get("password_field_count") or 0),
            "iframe_count": int(dom.get("iframe_count") or 0),
            "external_form_actions": [str(a)[:253] for a in (dom.get("external_form_actions") or [])[:20]],
        },
        "behaviour": {
            "popup_count": int(beh.get("popup_count") or 0),
            "download_attempt_count": int(beh.get("download_attempt_count") or 0),
            "download_filenames": [str(n)[:128] for n in (beh.get("download_filenames") or [])[:10]],
            "console_error_count": int(beh.get("console_error_count") or 0),
            "page_error_count": int(beh.get("page_error_count") or 0),
        },
        "limitations": lims,
    }
    return evidence, rendered_html, redirects


def run_container_scan(url: str, scan_id: str, allow_private: bool = False) -> tuple[str, dict, dict | None, str | None, int]:
    """Runs one disposable hardened Docker container and returns (status, evidence, ai2_dynamic, error, duration_ms)."""
    t0 = time.monotonic()
    url, defaulted_https = normalize_scan_url(url)
    ok, err_msg = validate_public_url(url, allow_private=allow_private)
    if not ok:
        return "failed", {}, None, err_msg, round((time.monotonic() - t0) * 1000)

    cname = f"safebrowse-scan-{scan_id}"
    cmd = [
        "docker", "run", "--rm",
        "--name", cname,
        "--user", "pwuser",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges:true",
        "--read-only",
        "--tmpfs", "/tmp:rw,noexec,nosuid,size=128m",
        "--tmpfs", "/home/pwuser/.cache:rw,noexec,nosuid,size=64m",
        "--memory=1024m",
        "--cpus=1.0",
        "--pids-limit=128",
        "--ipc=private",
        "-e", f"SCAN_URL={url}",
        "-e", f"SCAN_ID={scan_id}",
        "-e", f"SCAN_NAV_TIMEOUT_MS={NAV_TIMEOUT_MS}",
        "-e", f"SCAN_POST_LOAD_MS={POST_LOAD_MS}",
        "-e", f"SCAN_TOTAL_BUDGET_S={TOTAL_BUDGET_S}",
        IMAGE_NAME,
    ]
    if allow_private:
        cmd.insert(-1, "-e")
        cmd.insert(-1, "ALLOW_PRIVATE_FIXTURES=1")

    try:
        proc = subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=CONTAINER_TIMEOUT_S, encoding="utf-8", errors="replace")
        raw_out = proc.stdout or ""
        if len(raw_out.encode("utf-8", errors="ignore")) > MAX_STDOUT_BYTES:
            return "failed", {}, None, "Worker output exceeded size limit.", round((time.monotonic() - t0) * 1000)
        data = json.loads(raw_out)
        if not isinstance(data, dict) or data.get("schema_version") != 1:
            return "failed", {}, None, "Malformed worker output.", round((time.monotonic() - t0) * 1000)
        status = data.get("status") if data.get("status") in ALLOWED_STATUSES else "failed"
        evidence, rendered_html, redirects = _normalize_evidence(data)
        if defaulted_https:
            evidence.setdefault("limitations", []).append("Scanned using HTTPS by default (plain HTTP was not scanned).")
        ai2_dyn = _evaluate_ai2_on_rendered_dom(rendered_html, evidence["final_url"] or url, redirects)
        dur = int(data.get("duration_ms") or round((time.monotonic() - t0) * 1000))
        return status, evidence, ai2_dyn, data.get("error"), dur
    except subprocess.TimeoutExpired:
        return "timed_out", {"limitations": ["Dynamic scan container exceeded overall deadline."]}, None, "Dynamic scan timed out.", round((time.monotonic() - t0) * 1000)
    except Exception as exc:
        log.warning("Dynamic scan container error for %s: %s", scan_id, exc)
        return "failed", {}, None, "Dynamic scanner unavailable.", round((time.monotonic() - t0) * 1000)
    finally:
        # Always guarantee container cleanup on timeout/crash
        subprocess.run(["docker", "rm", "-f", cname], capture_output=True, timeout=10)


def _worker_task(job_id: str, url: str) -> None:
    try:
        dynamic_scans.set_running(job_id)
        status, evidence, ai2_dyn, error, dur = run_container_scan(url, job_id)
        dynamic_scans.finish_job(job_id, status, evidence, ai2_dyn, error, dur)
    except Exception as exc:
        log.exception("Dynamic scan background task failed for %s", job_id)
        dynamic_scans.finish_job(job_id, "failed", {}, None, f"Internal error: {type(exc).__name__}", None)


def enqueue(history_id, user_id, url: str):
    """Creates a queued dynamic scan job and submits it to the bounded thread pool."""
    job = dynamic_scans.create_job(history_id, user_id, url)
    _EXECUTOR.submit(_worker_task, str(job["id"]), url)
    return job
