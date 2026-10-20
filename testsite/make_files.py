"""Run once in the testsite folder:  python make_files.py   (creates files/ with harmless test files)"""
import base64, pathlib
d = pathlib.Path(__file__).resolve().parent / "files"
d.mkdir(exist_ok=True)
for n, c in {
    "setup.exe": "HARMLESS TEST FILE. Not a program.\n", "update.exe": "HARMLESS TEST FILE (auto-download test).\n",
    "installer.msi": "HARMLESS TEST FILE.\n", "run.bat": "@echo off\nREM HARMLESS TEST FILE\n",
    "tool.js": "// HARMLESS TEST FILE\n", "script.sh": "#!/bin/sh\n# HARMLESS TEST FILE\n",
    "app.apk": "HARMLESS TEST FILE.\n", "notes.txt": "Plain text: should download with NO warning.\n",
}.items():
    if n != "notes.txt":
        c += "harmless padding line, ignore.\n" * 70000   # about 2 MB, so it is not finished before the guard can react
    (d / n).write_text(c)
(d / "sample.pdf").write_bytes(b"%PDF-1.1\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 200 200]>>endobj\ntrailer<</Root 1 0 R>>\n%%EOF\n")
(d / "pixel.png").write_bytes(base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="))
print("created", len(list(d.iterdir())), "files in", d)
