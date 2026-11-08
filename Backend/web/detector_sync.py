"""Tells the detector (aidev) that a list changed, so the change works at once without restarting the Backend.
Never raises: a problem here must not fail the administrator's request (the detector also re-reads the
administrator-approved threat list by itself every 30 seconds)."""
from __future__ import annotations

import logging

log = logging.getLogger(__name__)


def refresh_threats() -> None:
    """After an approval / removal on the Global Threat List."""
    try:
        from aidev.detection import detector
        detector.refresh_threats()
    except Exception:
        log.exception("could not refresh the detector's threat list")


def reload_lists() -> None:
    """After an administrator changed the whitelist / not-trusted / blacklist lists (detection_lists)."""
    try:
        from aidev.detection import detector
        detector.reload_lists()
    except Exception:
        log.exception("could not reload the detector's lists")
