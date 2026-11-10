"""Builds the declarativeNetRequest rulesets (chrome/rules/ads.json, trackers.json) from EasyList / EasyPrivacy files.

    python tools/build_dnr.py <ads input> [<ads input> ...] --trackers <tracker input> [...] [--out chrome/rules]

An input is a raw filter list or the JSON that the GitHub tool saves ([{"text": "..."}]). Only whole-domain filters are
used (||domain^ with no path, optionally $third-party / $document / $popup); everything else is ignored on purpose, so
a rule can never block more than the domain it names. One DNR rule carries thousands of domains (requestDomains), so
the rulesets stay far below Chrome's static-rule limit. Lists: https://easylist.to (GPLv3 / CC BY-SA 3.0).
"""
import json
import re
import sys
from pathlib import Path

ALL = ["sub_frame", "script", "image", "stylesheet", "object", "xmlhttprequest", "ping", "media", "font", "websocket", "other"]
LINE = re.compile(r"\|\|((?:[a-z0-9-]+\.)+[a-z]{2,})\^(?:\$([a-z,~-]+))?$")
# domains that must never be blocked, whatever a list says (they host the pages people use)
NEVER = {"google.com", "youtube.com", "facebook.com", "microsoft.com", "apple.com", "amazon.com", "github.com", "cloudflare.com",
         "gstatic.com", "googleapis.com", "wikipedia.org", "twitter.com", "x.com", "instagram.com", "linkedin.com", "live.com"}
# well known ad / tracking networks that the EasyList "third party" files cover with path filters only
CORE = """doubleclick.net googlesyndication.com googleadservices.com googletagservices.com adservice.google.com
google-analytics.com adnxs.com rubiconproject.com pubmatic.com openx.net criteo.com criteo.net taboola.com outbrain.com
scorecardresearch.com quantserve.com amazon-adsystem.com ads-twitter.com advertising.com adsrvr.org casalemedia.com
moatads.com serving-sys.com 2mdn.net adform.net smartadserver.com teads.tv yieldmo.com media.net bidswitch.net
exelator.com bluekai.com demdex.net krxd.net rlcdn.com tapad.com mathtag.com sharethrough.com indexww.com""".split()


def text_of(path: Path) -> str:
    raw = path.read_text(encoding="utf-8", errors="ignore")
    try:
        data = json.loads(raw)
        parts = []
        for item in data:
            if isinstance(item, dict):
                parts.append(item.get("text", ""))
                parts.append((item.get("resource") or {}).get("text", ""))
        return "\n".join(parts)
    except ValueError:
        return raw


def parse(paths):
    plain, third, doc = set(), set(), set()
    for p in paths:
        for line in text_of(Path(p)).splitlines():
            m = LINE.match(line.strip())
            if not m:
                continue
            host, opts = m.group(1), (m.group(2) or "")
            if any(host == d or host.endswith("." + d) for d in NEVER):
                continue
            o = {x for x in opts.split(",") if x}
            if o - {"third-party", "document", "popup"}:
                continue                                    # any other option: skip, we do not guess
            if "document" in o or "popup" in o:
                doc.add(host)
            elif "third-party" in o:
                third.add(host)
            else:
                plain.add(host)
    return plain, third, doc


def collapse(domains):
    """requestDomains already covers subdomains, so a.b.com is dropped when b.com is listed."""
    s = set(domains)
    return sorted(d for d in s if not any(d[i + 1:] in s for i, ch in enumerate(d) if ch == "."))


def rules(first_id, plain, third, doc):
    out, n = [], first_id
    def add(domains, **cond):
        nonlocal n
        d = collapse(domains)
        if d:
            out.append({"id": n, "priority": 1, "action": {"type": "block"}, "condition": {"requestDomains": d, **cond}})
            n += 1
    add(plain, resourceTypes=ALL)
    add(third, resourceTypes=ALL, domainType="thirdParty")
    add(doc, resourceTypes=["main_frame", "sub_frame"])
    return out


def main(argv):
    out_dir = Path("chrome/rules")
    ads_in, trk_in = [], []
    cur = ads_in
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--trackers":
            cur = trk_in
        elif a == "--out":
            i += 1
            out_dir = Path(argv[i])
        else:
            cur.append(a)
        i += 1
    out_dir.mkdir(parents=True, exist_ok=True)
    ap, at, ad = parse(ads_in)
    tp, tt, td = parse(trk_in)
    tp |= set(CORE)
    ads = rules(1, ap, at - ap, ad)
    trk = rules(1000, tp, tt - tp, td)
    for name, r in (("ads", ads), ("trackers", trk)):
        (out_dir / f"{name}.json").write_text(json.dumps(r, separators=(",", ":")), encoding="utf-8")
        print(name, sum(len(x["condition"]["requestDomains"]) for x in r), "domains in", len(r), "rules")


if __name__ == "__main__":
    main(sys.argv[1:])
