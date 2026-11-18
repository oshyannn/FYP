from pathlib import Path

P = Path(r"D:\Desktop\FYP\AIDev\aidev\detection\predict_content.py")
raw = P.read_bytes().decode("utf-8")
eol = "\r\n" if "\r\n" in raw else "\n"

def fix(s):
    return s.replace("\n", eol)

IMP_OLD = fix("from aidev.detection import pagefetch\n")
IMP_NEW = fix("from aidev.detection import pagefetch\nfrom aidev.detection.docker import render_rescore\n")

RET_OLD = fix('''        return {"probability": p, "signals": sigs, "final_url": page.url, "download": auto,
                "download_kind": "auto" if auto else None, "model_version": version, "latency_ms": ms(), "features": f,
                "page_signals": page_signals.extract(page.html, page.url),
                "probability_calibrated": p_cal, "threshold": thr, "flagged": flagged}
''')
RET_NEW = fix('''        res = {"probability": p, "signals": sigs, "final_url": page.url, "download": auto,
               "download_kind": "auto" if auto else None, "model_version": version, "latency_ms": ms(), "features": f,
               "page_signals": page_signals.extract(page.html, page.url),
               "probability_calibrated": p_cal, "threshold": thr, "flagged": flagged}
        if f is not None:
            res.update(render_rescore.rescore(page.url, res))
        return res
''')

assert raw.count(IMP_OLD) == 1, "import line not found exactly once"
assert raw.count(RET_OLD) == 1, "return block not found exactly once"
assert "render_rescore" not in raw, "already patched"
raw = raw.replace(IMP_OLD, IMP_NEW).replace(RET_OLD, RET_NEW)
P.write_bytes(raw.encode("utf-8"))
print("patched OK")