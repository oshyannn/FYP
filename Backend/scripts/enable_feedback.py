"""Registers the feedback API in Backend/web/web_setup.py (safe to run more than once).

Run from the Backend folder:   python -m scripts.enable_feedback
It only inserts two lines after the last `app.register_blueprint(...)` inside init_web(); nothing else is touched.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

TARGET = Path(__file__).resolve().parents[1] / "web" / "web_setup.py"
MARK = "web.controllers.feedback"


def main() -> int:
    if not TARGET.exists():
        print(f"Cannot find {TARGET}")
        return 1
    text = TARGET.read_text(encoding="utf-8")
    if MARK in text:
        print("Feedback is already registered in web_setup.py. Nothing to do.")
        return 0
    lines = text.split("\n")
    last = max((i for i, ln in enumerate(lines) if re.match(r"\s+app\.register_blueprint\(", ln)), default=None)
    if last is None:
        print("Could not find an app.register_blueprint(...) line in web_setup.py.\n"
              "Add these two lines inside init_web() yourself:\n"
              "    from web.controllers.feedback import bp as feedback_bp\n"
              "    app.register_blueprint(feedback_bp)")
        return 1
    indent = re.match(r"\s+", lines[last]).group(0)
    lines[last + 1:last + 1] = [f"{indent}from web.controllers.feedback import bp as feedback_bp",
                                f"{indent}app.register_blueprint(feedback_bp)"]
    TARGET.write_text("\n".join(lines), encoding="utf-8")
    print("Feedback API registered in web_setup.py. Restart `python app.py`.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
