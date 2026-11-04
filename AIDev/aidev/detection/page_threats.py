"""
Page threat indicators for the page-content result (AI 2): WHAT KIND of danger a page looks like, each kind with its own
percentage and a plain-language description, so the screens can show more than one number.

    from aidev.detection.page_threats import assess
    cats = assess(features, download="setup.exe", download_kind="auto")     # list of dicts, see below

Where the numbers come from (be honest about this in the report): the weights below are chosen by hand and NOT calibrated on data,
so treat the percentages as "how many warning signs", not as probabilities. There is ONE trained content model (predict_content.py,
it gives the overall phishing probability). These per-kind percentages are NOT separate trained models. They are
rule-based indicator strengths computed from the same page features (content_features.py) that the model reads, so they
work even when the model file is missing, and each one lists the evidence that raised it. 0% = nothing of this kind seen,
100% = every warning sign of this kind is present. They explain the overall result; they do not change the verdict
(detector.py still decides from the model probability and the download check).

Each returned item:
    id, label           stable id and display name
    percent             0..100 (integer)
    level               "low" (<20) | "medium" (20..49) | "high" (>=50)
    triggered           True when percent >= TRIGGER_PERCENT
    description         what this kind of threat is, then what was (or was not) found on this page
    evidence            list of the individual findings that raised the percentage
"""
from __future__ import annotations

TRIGGER_PERCENT = 40


class _Score:
    """Adds up weighted findings; the total is capped at 100."""

    def __init__(self) -> None:
        self.points = 0
        self.evidence: list[str] = []

    def add(self, condition, points: int, text: str) -> None:
        if condition:
            self.points += points
            self.evidence.append(text)

    @property
    def percent(self) -> int:
        return max(0, min(100, int(self.points)))


def _level(percent: int) -> str:
    return "high" if percent >= 50 else "medium" if percent >= 20 else "low"


def _item(cid: str, label: str, what: str, s: _Score) -> dict:
    p = s.percent
    found = ("Found on this page: " + "; ".join(s.evidence) + ".") if s.evidence else "Nothing of this kind was found on this page."
    return {"id": cid, "label": label, "percent": p, "level": _level(p), "triggered": p >= TRIGGER_PERCENT,
            "description": f"{what} {found}", "evidence": list(s.evidence)}


def assess(features: dict | None, download: str | None = None, download_kind: str | None = None,
           signals: dict | None = None) -> list[dict]:
    """Per-kind indicators for one page. `features` = content_features.extract(...) (None when the page text was not
    read, e.g. the address itself is a file). download / download_kind come from predict_content ("direct" | "auto").
    `signals` = page_signals.extract(...): a more careful reading of hidden frames, obfuscation, sensitive fields and program
    links. When given it replaces the rough counts of the model features (which flag Google Tag Manager's hidden iframe and
    non-English text written as \\uXXXX escapes on perfectly normal sites)."""
    f = features or {}
    sig = signals or {}

    def g(name: str) -> float:
        try:
            return float(f.get(name, 0) or 0)
        except (TypeError, ValueError):
            return 0.0

    pw = g("has_password_field") > 0
    ext_form = g("form_external_action") > 0
    brand_title = g("brand_in_title_not_domain") > 0
    brand_text = g("brand_in_text_not_domain") > 0
    n_sens = int(sig["sensitive_inputs"]) if "sensitive_inputs" in sig else int(g("n_sensitive_inputs"))
    n_words = int(g("n_sensitive_words"))
    tls_bad = g("tls_invalid") > 0
    hidden_iframe = (sig["hidden_iframes"] > 0) if "hidden_iframes" in sig else g("hidden_iframe") > 0
    many_external = g("ext_resource_ratio") > 0.6 and g("n_images") + g("n_scripts") > 3
    obf = float(sig["obfuscation_density"]) if "obfuscation_density" in sig else g("obfuscation_density")
    exec_links = int(sig["exec_links"]) if "exec_links" in sig else int(g("n_download_links"))
    # Words and brand names are only evidence when the page also ASKS for something (a password or a sensitive field).
    # A news article about a bank, or a review that names Google, is normal text.
    asks = pw or n_sens >= 1

    # 1. Fake login page (stealing a username and password)
    login = _Score()
    login.add(pw, 15, "has a password field (normal for a real login page, so this alone is a weak sign)")
    login.add(pw and ext_form, 35, "the password form sends what you type to a different website")
    login.add(pw and not ext_form and (g("form_null_action") > 0 or g("form_script_or_mail_action") > 0), 15,
              "the password form submits to a script, an e-mail address or nowhere")
    login.add(pw and brand_title, 25, "the page title names a well-known brand that this domain does not belong to")
    login.add(pw and g("title_login_word") > 0, 5, "the title says login / verify / secure / confirm")
    login.add(pw and g("thin_page") > 0, 5, "almost nothing on the page except the login box")
    login.add(pw and tls_bad, 10, "invalid HTTPS certificate on a page that asks for a password")

    # 2. Fake bank / payment page (card, OTP, bank account, ID number or wallet recovery phrase)
    bank = _Score()
    bank.add(n_sens == 1, 30, "asks for a sensitive detail (card number, CVV, OTP, IBAN, ID / MyKad number or recovery phrase)")
    bank.add(n_sens >= 2, 45, f"asks for {n_sens} sensitive details (card number, CVV, OTP, IBAN, ID / MyKad number or recovery phrase)")
    bank.add(asks and n_words >= 8, 20, "asks for details on a page full of banking / security words (account, verify, card, OTP ...)")
    bank.add(asks and 3 <= n_words < 8, 10, "asks for details on a page that uses several banking / security words")
    bank.add(asks and (brand_title or brand_text), 15, "asks for details on a page that names a well-known brand or bank this domain does not belong to")
    bank.add(n_sens >= 1 and ext_form, 25, "the form sends the entered details to a different website")
    bank.add(n_sens >= 1 and tls_bad, 10, "invalid HTTPS certificate on a page that asks for payment or bank details")

    # 3. Hidden / automatic download (malware delivery)
    dl = _Score()
    name = download or "a program file"
    dl.add(download_kind == "direct", 40, f"the address itself downloads a program file ({name}) instead of opening a page")
    dl.add(download_kind == "auto", 70, f"the page starts the download of a program file ({name}) by itself, without a click")
    dl.add(exec_links >= 1, 15, f"links to {exec_links} program file(s) (.exe, .msi, .apk, .dmg ...)")
    dl.add(g("install_words") > 0, 10, "asks you to install a plug-in or extension, or to 'update your browser'")
    dl.add(hidden_iframe, 10, "contains a hidden frame that is not a tag-manager or tracking frame")

    # 4. Hidden or deceptive page behaviour
    dec = _Score()
    dec.add(obf > 3, 35, "heavily obfuscated JavaScript (eval / unescape / atob / hex escapes in code written to hide what it does)")
    dec.add(1 < obf <= 3, 15, "some obfuscated JavaScript")
    dec.add(hidden_iframe, 20, "contains a hidden frame that is not a tag-manager or tracking frame")
    dec.add(g("rightclick_blocked") > 0, 10, "blocks right-click so the page is harder to inspect")
    dec.add(g("js_redirect") > 0, 10, "sends you to another page with JavaScript")
    dec.add(g("meta_refresh") > 0, 10, "redirects automatically (meta refresh)")
    dec.add(g("redirect_cross_domain") > 0, 15, "redirected you to a different website")
    dec.add(tls_bad, 10, "invalid HTTPS certificate")

    # 5. Brand impersonation
    brand = _Score()
    brand.add(brand_title and asks, 50, "the page title names a well-known brand that this domain does not belong to, and the page asks for a password or sensitive details")
    brand.add(brand_title and not asks, 15, "the page title names a well-known brand (normal for news and review pages that only mention it)")
    brand.add(brand_text and asks, 20, "the top of the page talks about a well-known brand that this domain does not belong to")
    brand.add((brand_title or brand_text) and asks and g("favicon_external") > 0, 15, "the site icon is loaded from another website")
    brand.add((brand_title or brand_text) and asks and many_external, 15, "most images and scripts come from other websites (copied page)")

    return [
        _item("fake_login", "Fake login page",
              "Looks for a page that copies a sign-in screen to steal a username and password.", login),
        _item("fake_bank", "Fake bank / payment page",
              "Looks for a page that asks for card, bank, OTP, ID or wallet details, the way a fake bank or payment page does.", bank),
        _item("auto_download", "Hidden / automatic download",
              "Looks for a page that pushes a program file to your computer, or tricks you into installing something.", dl),
        _item("deceptive_behaviour", "Hidden or deceptive behaviour",
              "Looks for code and tricks that hide what the page really does (obfuscation, hidden frames, silent redirects).", dec),
        _item("brand_impersonation", "Brand impersonation",
              "Looks for a page that pretends to belong to a well-known brand or bank.", brand),
    ]
