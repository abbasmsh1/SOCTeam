"""
Archive old SOC reports into monthly subdirs to keep `Reports/` scannable.

Usage:
    python -m Implementation.tools.rotate_reports --older-than-days 7

Reports older than N days (by filename timestamp, falling back to mtime) are
moved to Reports/archive/YYYY-MM/. The `list_reports` endpoint skips the
archive subdir so the main scan stays fast.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import os
import re
import shutil
import sys
from pathlib import Path
from typing import Optional

REPORT_DIR = Path("E:/IMT/2nd Sem/Project/Reports")
ARCHIVE_DIR = REPORT_DIR / "archive"
FNAME_RE = re.compile(r"SOC_Report_(\d{8})_(\d{6})_\d+\.md$")


def _parse_ts(fname: str) -> Optional[_dt.datetime]:
    m = FNAME_RE.match(fname)
    if not m:
        return None
    try:
        return _dt.datetime.strptime(m.group(1) + m.group(2), "%Y%m%d%H%M%S")
    except Exception:
        return None


def rotate(older_than_days: int = 7, dry_run: bool = False) -> dict:
    cutoff = _dt.datetime.now() - _dt.timedelta(days=older_than_days)
    ARCHIVE_DIR.mkdir(parents=True, exist_ok=True)

    scanned = moved = errors = 0
    by_month: dict[str, int] = {}
    for entry in REPORT_DIR.iterdir():
        if not entry.is_file() or entry.suffix != ".md":
            continue
        scanned += 1
        ts = _parse_ts(entry.name)
        if ts is None:
            # Fall back to mtime
            try:
                ts = _dt.datetime.fromtimestamp(entry.stat().st_mtime)
            except OSError:
                errors += 1
                continue
        if ts >= cutoff:
            continue
        bucket = ts.strftime("%Y-%m")
        target_dir = ARCHIVE_DIR / bucket
        target_dir.mkdir(parents=True, exist_ok=True)
        target = target_dir / entry.name
        try:
            if not dry_run:
                shutil.move(str(entry), str(target))
            moved += 1
            by_month[bucket] = by_month.get(bucket, 0) + 1
        except OSError as exc:
            print(f"[rotate] failed to move {entry.name}: {exc}", file=sys.stderr)
            errors += 1

    return {
        "scanned": scanned,
        "moved": moved,
        "errors": errors,
        "by_month": by_month,
        "cutoff_iso": cutoff.isoformat(),
        "dry_run": dry_run,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--older-than-days", type=int, default=7)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    result = rotate(older_than_days=args.older_than_days, dry_run=args.dry_run)
    print(
        f"[rotate] scanned={result['scanned']} moved={result['moved']} "
        f"errors={result['errors']} cutoff={result['cutoff_iso']}"
    )
    for month, count in sorted(result["by_month"].items()):
        print(f"  -> {month}: {count} files")
    return 0 if result["errors"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
