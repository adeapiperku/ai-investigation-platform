"""Parse a Chromium-based browser's History SQLite file (Edge, in this
case) for visited URLs.

The History file is copied to a temp file before opening it, since the
original lives inside the read-only evidence collection and SQLite
needs to write its own lock/journal files alongside the DB.
"""
from __future__ import annotations

import os
import shutil
import sqlite3
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Optional

CHROME_EPOCH = datetime(1601, 1, 1)


def chrome_time_to_iso(value: Optional[int]) -> Optional[str]:
    if not value:
        return None
    return (CHROME_EPOCH + timedelta(microseconds=value)).isoformat() + "Z"


def resolve_edge_history_path(case_root: Path, username: str) -> Path:
    return (
        Path(case_root)
        / "uploads" / "auto" / "C%3A" / "Users" / username
        / "AppData" / "Local" / "Microsoft" / "Edge" / "User Data" / "Default" / "History"
    )


def read_history(history_path: Path, limit: int = 200) -> list[dict[str, Any]]:
    """Return visited URLs ordered by most recent first."""
    if not history_path.exists():
        return []

    tmp_path = tempfile.mktemp(suffix=".sqlite")
    shutil.copy(history_path, tmp_path)
    try:
        conn = sqlite3.connect(tmp_path)
        cur = conn.cursor()
        cur.execute(
            "SELECT url, title, visit_count, last_visit_time "
            "FROM urls ORDER BY last_visit_time DESC LIMIT ?",
            (limit,),
        )
        rows = cur.fetchall()
        conn.close()
    finally:
        os.remove(tmp_path)

    return [
        {
            "url": url,
            "title": title,
            "visit_count": visit_count,
            "last_visit_time_utc": chrome_time_to_iso(last_visit_time),
        }
        for url, title, visit_count, last_visit_time in rows
    ]


if __name__ == "__main__":
    import json
    import sys

    case_root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(
        "TriDsk-WKS02-C.1dfcd21bd3d01cc0-F.D3JVHAK4B16NM"
    )
    username = sys.argv[2] if len(sys.argv) > 2 else "yscott"

    history_path = resolve_edge_history_path(case_root, username)
    entries = read_history(history_path)
    print(json.dumps(entries, indent=2))
    print(f"\n{len(entries)} history entries found for {username}", file=sys.stderr)
