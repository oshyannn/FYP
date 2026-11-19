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

from web.db_models import dynamic_scans, scans

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
    # Keep inner worker watchdog at least 10s below outer Docker kill timeout so partial DOM always flushes
    effective_budget_s = min(TOTAL_BUDGET_S, max(10.0, CONTAINER_TIMEOUT_S - 10.0))
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
        "-e", f"SCAN_TOTAL_BUDGET_S={effective_budget_s}",
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


def merge_dynamic_ai2_into_analysis(
    analysis: dict, ai2_dyn: dict, cur_level: str, cur_score: float
) -> tuple[str, float, dict]:
    """Replaces the static AI 2 scan result with the Docker rendered-DOM AI 2 result and recalculates the final score."""
    aidev_dir = str(Path(__file__).resolve().parents[3] / "AIDev")
    if aidev_dir not in sys.path:
        sys.path.insert(0, aidev_dir)
    from aidev.detection import detector as det

    out = dict(analysis or {})
    orig_ai2 = out.get("ai2") if isinstance(out.get("ai2"), dict) else {}

    p_eff = ai2_dyn.get("probability_calibrated")
    if p_eff is None:
        p_eff = ai2_dyn.get("probability")
    ai2_score = det._content_to_score(float(p_eff)) if p_eff is not None else 0
    cal_pct = ai2_dyn.get("calibrated_percent")
    display_pct = cal_pct if cal_pct is not None else ai2_dyn.get("percent")
    cats = list(ai2_dyn.get("categories") or [])
    page_rules_score = det._page_rules_bonus(cats)

    desc = (
        f"Evaluated on browser-rendered DOM via Docker dynamic scan ({display_pct}% phishing probability; "
        f"replaces static page scan)."
    )
    out["ai2"] = {
        "name": orig_ai2.get("name") or "AI 2: page content model",
        "state": "ok",
        "available": True,
        "probability": display_pct,
        "percent": display_pct,
        "score": ai2_score,
        "level": det._ai_level(ai2_score),
        "description": desc,
        "signals": list(ai2_dyn.get("signals") or [])[:10],
        "categories": cats,
        "download": orig_ai2.get("download"),
        "page_read": True,
        "source": "docker_dynamic",
    }

    if isinstance(out.get("checks"), list):
        new_checks = []
        for chk in out["checks"]:
            if isinstance(chk, dict) and chk.get("id") == "ai2":
                new_checks.append({
                    **chk,
                    "state": "match" if ai2_score >= det.THRESHOLD_SUSPICIOUS else "clear",
                    "score": ai2_score,
                    "effect": "risk" if ai2_score >= det.THRESHOLD_SUSPICIOUS else "none",
                    "detail": desc,
                })
            else:
                new_checks.append(chk)
        out["checks"] = new_checks

    ai1 = out.get("ai1") if isinstance(out.get("ai1"), dict) else {}
    ai1_score = ai1.get("score") if ai1.get("state") == "ok" and isinstance(ai1.get("score"), (int, float)) else None
    ai_comb = det._ai_combined(int(ai1_score) if ai1_score is not None else None, ai2_score)
    out["ai_combined"] = ai_comb

    note = f"AI 2 updated from Docker dynamic browser scan ({display_pct}%), replacing static page scan."
    reasons = list(out.get("reasons") or [])
    if note not in reasons:
        reasons.append(note)
    out["reasons"] = reasons

    # Recalculate final score using the same weighted formula (unless locked by hard blacklist/adult/admin list)
    hard_list = out.get("source") in ("blacklist", "adult-list", "admin-list")
    final = dict(out.get("final") or {}) if isinstance(out.get("final"), dict) else {}
    list_api = dict(final.get("list_api") or {}) if isinstance(final.get("list_api"), dict) else {}
    is_trusted = bool(list_api.get("trusted")) or out.get("source") in ("whitelist", "trusted-suffix")
    trust_discount = int(list_api.get("trust_discount") or (25 if is_trusted else 0))
    list_score = list_api.get("score") if isinstance(list_api.get("score"), (int, float)) else None
    if is_trusted and list_score is not None and list_score <= 10:
        list_score = None  # fast-path whitelist score (5/10) is trust credit, not a risk score

    ai_score = ai_comb.get("score")
    new_level = cur_level
    new_score = cur_score

    if not hard_list:
        bonus = 0
        if list_score is not None and list_score >= det.THRESHOLD_MALICIOUS:
            final_score = max(int(list_score), int(ai_score or 0))
        elif ai_score is not None and list_score is not None:
            bonus = 15 if (ai_score >= 50 and list_score >= 40) else 0
            final_score = max(0, min(100, int(round(0.55 * ai_score + 0.45 * list_score + page_rules_score + bonus - trust_discount))))
        elif ai_score is not None:
            final_score = max(0, min(100, int(round(ai_score + page_rules_score - trust_discount))))
        else:
            final_score = int(round(cur_score))

        new_score = float(final_score)
        status_str = det._status(final_score)
        new_level = status_str.lower()
        out["status"] = status_str
        out["risk_score"] = final_score
        out["has_data"] = True

        final["status"] = status_str
        final["score"] = final_score
        final["list_api"] = {**list_api, "score": list_score, "trusted": is_trusted, "trust_discount": trust_discount}
        final["ai"] = {"score": ai_score, "text": ai_comb["description"]}
        final["page_rules_score"] = page_rules_score
        final["bonus"] = bonus
        notes = [n for n in (final.get("notes") or []) if "Docker dynamic browser scan" not in n]
        notes.append(note)
        if page_rules_score > 0:
            notes.append(f"Rule-based page checks triggered (+{page_rules_score} risk points)")
        final["notes"] = notes
        out["final"] = final
    else:
        if final:
            final["ai"] = {"score": ai_score, "text": ai_comb["description"]}
            final["page_rules_score"] = page_rules_score
            out["final"] = final

    return new_level, new_score, out


def _apply_dynamic_ai2_to_scan(history_id, user_id, ai2_dyn: dict) -> None:
    try:
        row = scans.get_one(user_id, history_id)
        if not row or not isinstance(row.get("analysis"), dict):
            return
        cur_level = str(row["risk_level"])
        cur_score = float(row["risk_score"] or 0)
        new_level, new_score, updated_analysis = merge_dynamic_ai2_into_analysis(
            row["analysis"], ai2_dyn, cur_level, cur_score
        )
        scans.update_scan_result(user_id, history_id, level=new_level, score=new_score, analysis=updated_analysis)
    except Exception as exc:
        log.warning("Failed to merge dynamic AI 2 into scan %s: %s", history_id, exc)


def _worker_task(job_id: str, history_id, user_id, url: str) -> None:
    try:
        dynamic_scans.set_running(job_id)
        status, evidence, ai2_dyn, error, dur = run_container_scan(url, job_id)
        dynamic_scans.finish_job(job_id, status, evidence, ai2_dyn, error, dur)
        if ai2_dyn is not None:
            _apply_dynamic_ai2_to_scan(history_id, user_id, ai2_dyn)
    except Exception as exc:
        log.exception("Dynamic scan background task failed for %s", job_id)
        dynamic_scans.finish_job(job_id, "failed", {}, None, f"Internal error: {type(exc).__name__}", None)


def enqueue(history_id, user_id, url: str):
    """Creates a queued dynamic scan job and submits it to the bounded thread pool."""
    job = dynamic_scans.create_job(history_id, user_id, url)
    _EXECUTOR.submit(_worker_task, str(job["id"]), history_id, user_id, url)
    return job
