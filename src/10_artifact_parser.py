"""Chromium/Edge ``History`` database parsing.

Several questions (the repository the user was tricked into downloading, the
stealer download URL, the exfiltration endpoint) can only be answered from
*binary* artifacts collected under ``data/raw/uploads/auto/...`` — here, the
Edge ``History`` SQLite databases.

Like every other parser in this package, the functions here emit **raw payload
dicts**; turning them into normalized records is the dataset builder's job. That
keeps one normalization path for all twelve datasets rather than one per source.
Unreadable or non-SQLite files are reported as collection problems, never raised.
"""

from __future__ import annotations

import os
import re
import shutil
import sqlite3
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

from .loaders import CollectionProblem

# SQLite file header magic (first 16 bytes of any SQLite 3 database).
_SQLITE_MAGIC = b"SQLite format 3\x00"

# Chromium timestamps are microseconds since 1601-01-01 UTC (the Windows epoch).
_CHROME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)

_USER_RE = re.compile(r"[\\/]Users[\\/]([^\\/]+)", re.IGNORECASE)


def _chrome_time_to_iso(value: Any) -> str | None:
    """Convert a Chromium microsecond timestamp to UTC ISO-8601 (or ``None``)."""
    if not isinstance(value, (int, float)) or value <= 0:
        return None
    try:
        dt = _CHROME_EPOCH + timedelta(microseconds=int(value))
    except (OverflowError, ValueError):
        return None
    return dt.isoformat().replace("+00:00", "Z")


def _is_sqlite(path: Path) -> bool:
    """Return whether ``path`` starts with the SQLite file magic."""
    try:
        with path.open("rb") as handle:
            return handle.read(16) == _SQLITE_MAGIC
    except OSError:
        return False


def _username_from_path(path: Path) -> str | None:
    """Extract the profile owner from a ``\\Users\\<name>\\`` path."""
    match = _USER_RE.search(path.as_posix())
    return match.group(1) if match else None


def discover_browser_history(raw_dir: Path) -> List[Path]:
    """Find Chromium/Edge ``History`` SQLite databases under ``raw_dir``."""
    found: List[Path] = []
    for path in sorted(raw_dir.rglob("History")):
        if not path.is_file():
            continue
        # Only browser-profile History files (skip IE/Defender "History").
        if "User Data" not in path.as_posix():
            continue
        if _is_sqlite(path):
            found.append(path)
    return found


def _query(conn: sqlite3.Connection, sql: str) -> List[tuple]:
    """Run a query, returning ``[]`` if the table/columns are absent."""
    try:
        return conn.execute(sql).fetchall()
    except sqlite3.Error:
        return []


def _open_readonly(path: Path, source: str) -> Tuple[sqlite3.Connection | None, Path | None, List[CollectionProblem]]:
    """Copy a possibly-live database aside and open it read-only."""
    # Windows keeps mkstemp's descriptor open, so close it before copying over.
    fd, tmp_name = tempfile.mkstemp(suffix=".sqlite")
    os.close(fd)
    tmp = Path(tmp_name)
    try:
        shutil.copy(path, tmp)
        conn = sqlite3.connect(f"file:{tmp}?mode=ro&immutable=1", uri=True)
    except (OSError, sqlite3.Error) as exc:
        tmp.unlink(missing_ok=True)
        return None, None, [CollectionProblem(source, "unreadable_artifact", str(exc))]
    return conn, tmp, []


def collect_browser_history(
    files: List[Path], root: Path
) -> Tuple[List[Dict[str, Any]], List[CollectionProblem]]:
    """Read the ``urls`` table of every History database into raw payload dicts."""
    records: List[Dict[str, Any]] = []
    problems: List[CollectionProblem] = []

    for path in files:
        source = _relative(path, root)
        conn, tmp, issues = _open_readonly(path, source)
        problems.extend(issues)
        if conn is None:
            continue
        try:
            rows = _query(
                conn,
                "SELECT id, url, title, visit_count, typed_count, last_visit_time "
                "FROM urls",
            )
            for row_id, url, title, visit_count, typed_count, last_visit in rows:
                if not url:
                    continue
                records.append(
                    {
                        "url": url,
                        "title": title,
                        "visit_count": visit_count,
                        "typed_count": typed_count,
                        "last_visit_utc": _chrome_time_to_iso(last_visit),
                        "username": _username_from_path(path),
                        "row_id": row_id,
                        "_artifact_source": source,
                    }
                )
        finally:
            conn.close()
            if tmp is not None:
                tmp.unlink(missing_ok=True)

    return records, problems


def collect_browser_downloads(
    files: List[Path], root: Path
) -> Tuple[List[Dict[str, Any]], List[CollectionProblem]]:
    """Read the ``downloads`` table of every History database into raw dicts.

    The download's originating URL comes from ``downloads_url_chains``, which
    preserves the whole redirect chain — the final hop is what the user clicked,
    the first hop is where the file really came from.
    """
    records: List[Dict[str, Any]] = []
    problems: List[CollectionProblem] = []

    for path in files:
        source = _relative(path, root)
        conn, tmp, issues = _open_readonly(path, source)
        problems.extend(issues)
        if conn is None:
            continue
        try:
            chains: Dict[int, List[str]] = {}
            for row_id, url in _query(
                conn,
                "SELECT id, url FROM downloads_url_chains ORDER BY id, chain_index",
            ):
                chains.setdefault(row_id, []).append(url)

            rows = _query(
                conn,
                "SELECT id, target_path, start_time, end_time, received_bytes, "
                "total_bytes, state, danger_type, opened, referrer, tab_url, "
                "mime_type, original_mime_type FROM downloads",
            )
            for row in rows:
                (row_id, target_path, start, end, received, total, state,
                 danger, opened, referrer, tab_url, mime, original_mime) = row
                chain = chains.get(row_id, [])
                records.append(
                    {
                        "url": chain[0] if chain else None,
                        "final_url": chain[-1] if chain else None,
                        "url_chain": chain,
                        "target_path": target_path,
                        "start_time_utc": _chrome_time_to_iso(start),
                        "end_time_utc": _chrome_time_to_iso(end),
                        "received_bytes": received,
                        "total_bytes": total,
                        "state": state,
                        "danger_type": danger,
                        "opened": opened,
                        "referrer": referrer,
                        "tab_url": tab_url,
                        "mime_type": mime or original_mime,
                        "username": _username_from_path(path),
                        "row_id": row_id,
                        "_artifact_source": source,
                    }
                )
        finally:
            conn.close()
            if tmp is not None:
                tmp.unlink(missing_ok=True)

    return records, problems


def _relative(path: Path, root: Path) -> str:
    """Return a POSIX-style path relative to the raw data root."""
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.name
