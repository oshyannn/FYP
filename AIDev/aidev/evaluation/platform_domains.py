"""
Domains that host many phishing pages (own rule, pandas only): link shorteners, QR-code redirectors, form / survey builders,
free page hosts. A phishing page saved from such a domain is usually the PLATFORM's own page (interstitial, redirect, empty
form), so a model that reads the page text cannot be expected to see the phishing.

    platform_domains(domains, labels, min_pages=5) -> set of domains

Rule: a domain is a platform when at least `min_pages` pages of the data set that are labelled phishing sit on it. The rule
uses only the domain and the label, never a model's prediction. It was chosen AFTER the first error analysis showed how many
missed pages come from such domains, so results that use it are exploratory and must be reported next to the unfiltered ones.
"""
from __future__ import annotations

from urllib.parse import urlsplit

import numpy as np
import pandas as pd


def platform_domains(domains, labels, min_pages: int = 5) -> set[str]:
    d = pd.Series(list(domains)).astype(str)
    phish = d[np.asarray(labels).astype(int) == 1]
    counts = phish.value_counts()
    return {str(k) for k in counts[counts >= min_pages].index}


def url_domain(url) -> str:
    """Registered domain of the address that was SUBMITTED (not where it landed). The `group` column holds the landing
    domain, so a qrco.de link that redirects to linkedin.com has group linkedin.com; the platform is the submitted host."""
    from aidev.detection.content_features import _reg
    try:
        return _reg(urlsplit(str(url)).hostname)
    except ValueError:
        return ""
