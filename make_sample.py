#!/usr/bin/env python3
"""
make_sample.py - copy a data folder into a NEW folder, keeping only the first N rows of each file.

Run from the repo root (the folder that contains AIDev/):

    python make_sample.py                         # AIDev/data  ->  AIDev/data_sample, 50 rows per file
    python make_sample.py AIDev/data out_folder   # choose source and destination
    python make_sample.py AIDev/data out_folder --rows 20

What it does
  * .csv / .tsv        header line + first N rows (reads real CSV records, so a row whose
                       HTML field contains line breaks still counts as ONE row)
  * .txt / .list       first N lines
  * .jsonl / .ndjson   first N lines
  * .json / .md        copied whole if small (< 200 KB), otherwise listed as skipped
  * anything else      (.html.gz pages, model.joblib, images ...) grouped per folder in the report;
                       only the first --keep-other files of each group (default 5, each under 300 KB)
                       are copied, so you can still see what they look like
  * very long cells    (e.g. page HTML) are cut to --max-cell characters (default 500)
  * private files      .env*, benign_extra.csv (Chrome history), and names containing
                       history / cookie / password / secret / token / api_key are NEVER copied

It also writes SAMPLE_REPORT.txt inside the new folder: every file, its total line count,
how many rows were kept, and the column names. Upload the new folder (or just the report).
The original folder is only read, never changed.
"""
from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

CSV_EXT = {".csv", ".tsv"}
LINE_EXT = {".txt", ".list", ".lst", ".jsonl", ".ndjson"}
SMALL_COPY_EXT = {".json", ".md"}
SMALL_LIMIT = 200 * 1024
OTHER_LIMIT = 300 * 1024
SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv"}
PRIVATE_WORDS = ("history", "cookie", "password", "secret", "token", "api_key", "apikey")


def raise_csv_limit() -> None:
    """Allow very large CSV cells (page HTML). maxsize overflows on Windows, so step down."""
    m = sys.maxsize
    while True:
        try:
            csv.field_size_limit(m)
            return
        except OverflowError:
            m //= 10


def is_private(p: Path) -> bool:
    name = p.name.lower()
    return name.startswith(".env") or name.startswith("benign_extra") or any(w in name for w in PRIVATE_WORDS)


def count_lines(p: Path) -> int:
    """Fast physical line count (a record with line breaks inside a cell counts as several lines)."""
    n, last = 0, b"\n"
    with open(p, "rb") as f:
        while True:
            chunk = f.read(1 << 20)
            if not chunk:
                break
            n += chunk.count(b"\n")
            last = chunk[-1:]
    if last != b"\n":
        n += 1
    return n


def sample_csv(src: Path, dst: Path, n: int, max_cell: int) -> tuple[int, list[str]]:
    with open(src, "r", encoding="utf-8", errors="replace", newline="") as f:
        head = f.read(8192)
        f.seek(0)
        if src.suffix.lower() == ".tsv":
            delim = "\t"
        else:
            try:
                delim = csv.Sniffer().sniff(head, delimiters=",;\t|").delimiter
            except csv.Error:
                delim = ","
        reader = csv.reader(f, delimiter=delim)
        rows, header = [], []
        for i, row in enumerate(reader):
            if i == 0:
                header = row[:]
            if i > n:                       # row 0 is the header, then n data rows
                break
            rows.append([c if len(c) <= max_cell else c[:max_cell] + "...[cut]" for c in row])
    dst.parent.mkdir(parents=True, exist_ok=True)
    with open(dst, "w", encoding="utf-8", newline="") as out:
        csv.writer(out, delimiter=delim, lineterminator="\n").writerows(rows)
    return max(len(rows) - 1, 0), header


def sample_lines(src: Path, dst: Path, n: int, max_cell: int) -> int:
    dst.parent.mkdir(parents=True, exist_ok=True)
    kept = 0
    with open(src, "r", encoding="utf-8", errors="replace") as f, open(dst, "w", encoding="utf-8", newline="") as out:
        for line in f:
            if kept >= n:
                break
            line = line.rstrip("\r\n")
            if len(line) > max_cell:
                line = line[:max_cell] + "...[cut]"
            out.write(line + "\n")
            kept += 1
    return kept


def main() -> int:
    ap = argparse.ArgumentParser(description="Copy a data folder keeping only the first N rows of each file.")
    ap.add_argument("source", nargs="?", default="AIDev/data", help="folder to read (default AIDev/data)")
    ap.add_argument("dest", nargs="?", default=None, help="new folder to create (default <source>_sample)")
    ap.add_argument("--rows", type=int, default=50, help="data rows to keep per file (default 50)")
    ap.add_argument("--keep-other", type=int, default=5, help="other file types: copy only the first K per folder (default 5)")
    ap.add_argument("--max-cell", type=int, default=500, help="cut cells/lines longer than this (default 500)")
    a = ap.parse_args()

    src_root = Path(a.source).resolve()
    if not src_root.is_dir():
        print(f"Source folder not found: {src_root}")
        return 1
    dst_root = Path(a.dest).resolve() if a.dest else src_root.with_name(src_root.name + "_sample")
    if dst_root == src_root:
        print("Destination must be a different folder from the source.")
        return 1

    raise_csv_limit()
    report = [f"Sample of: {src_root}", f"Rows kept per file: {a.rows} (plus header for csv/tsv); long cells cut at {a.max_cell} chars", ""]
    table = []
    groups: dict[tuple[str, str], list[int]] = {}   # (folder, extension) -> [files, bytes, copied]
    for p in sorted(src_root.rglob("*")):
        if not p.is_file():
            continue
        rel = p.relative_to(src_root)
        if any(part in SKIP_DIRS for part in rel.parts) or dst_root in p.resolve().parents:
            continue
        ext, size = p.suffix.lower(), p.stat().st_size
        dst = dst_root / rel
        try:
            if is_private(p):
                table.append((str(rel), size, "-", "-", "EXCLUDED (private file name)"))
            elif ext in CSV_EXT:
                total = count_lines(p)
                kept, header = sample_csv(p, dst, a.rows, a.max_cell)
                table.append((str(rel), size, total, kept, "columns: " + " | ".join(h[:40] for h in header)))
            elif ext in LINE_EXT:
                total = count_lines(p)
                kept = sample_lines(p, dst, a.rows, a.max_cell)
                table.append((str(rel), size, total, kept, "lines"))
            elif ext in SMALL_COPY_EXT and size <= SMALL_LIMIT:
                dst.parent.mkdir(parents=True, exist_ok=True)
                dst.write_bytes(p.read_bytes())
                table.append((str(rel), size, "-", "whole file", "copied (small)"))
            else:
                g = groups.setdefault((str(rel.parent), ext or "(no ext)"), [0, 0, 0])
                g[0] += 1
                g[1] += size
                if g[2] < a.keep_other and size <= OTHER_LIMIT:
                    dst.parent.mkdir(parents=True, exist_ok=True)
                    dst.write_bytes(p.read_bytes())
                    g[2] += 1
        except Exception as e:  # one bad file must not stop the rest
            table.append((str(rel), size, "-", "-", f"ERROR: {e}"))

    for (folder, ext), (cnt, tot, copied) in sorted(groups.items()):
        table.append((f"{folder}/*{ext}  ({cnt} files)", tot, "-", f"{copied} files", f"other type: first {copied} copied whole, rest skipped"))
    report.append(f"{'file':55s} {'bytes':>12s} {'lines':>10s} {'kept':>10s}  note")
    for rel, size, total, kept, note in table:
        report.append(f"{rel:55s} {size:>12,d} {str(total):>10s} {str(kept):>10s}  {note}")
    dst_root.mkdir(parents=True, exist_ok=True)
    text = "\n".join(report) + "\n"
    (dst_root / "SAMPLE_REPORT.txt").write_text(text, encoding="utf-8")
    sys.stdout.buffer.write(text.encode("utf-8", errors="replace"))
    print(f"\nDone. New folder: {dst_root}")
    print("Zip that folder (or paste SAMPLE_REPORT.txt) and send it.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
