from dotenv import load_dotenv

load_dotenv()                      # reads backend/.env (also makes PHISHTANK_API_KEY available)

from flask import Flask, request, jsonify

import config
from detector import analyze

app = Flask(__name__)


@app.route("/analyze", methods=["POST"])
def analyze_endpoint():
    url = ((request.get_json(silent=True) or {}).get("url") or "").strip()
    if not url:
        return jsonify({"status": "error", "message": "Missing URL"}), 400

    result = analyze(url)
    print(f"{result['status']:10s} {result['risk_score']:>3}  [{result['source']}]  {url}")
    for r in result["reasons"]:
        print("            -", r)
    return jsonify(result)


if config.auth_ready():
    from web_setup import init_web
    init_web(app)
    if config.REQUIRE_AUTH_FOR_ANALYZE:            # only a logged-in desktop user or a paired extension may scan
        from guards import auth_required
        app.view_functions["analyze_endpoint"] = auth_required("extension", "user")(analyze_endpoint)
else:
    print("WARNING: SECRET_KEY / DATABASE_URL are not set, so the account API is OFF and only /analyze runs.\n"
          "         Copy .env.example to .env and fill it in.")


if __name__ == "__main__":
    app.run(debug=True)   # set debug=False when you are done developing
