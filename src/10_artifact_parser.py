"""Binary artifact parsing (browser history / downloads).

The Phase 1 loaders only understand JSON/JSONL. Several investigation questions
(the malicious download URL, the browsing timeline) can only be answered from
*binary* artifacts collected under ``data/raw/uploads/auto/...`` — in this
collection, the Chromium/Edge ``History`` SQLite databases.

This module parses those databases with the standard-library ``sqlite3`` module
(no third-party dependencies) and emits records in the **same normalized schema**
used by Phase 1, so browser evidence flows through the graph, cleaning and agent
stages exactly like every other record. It never raises: unreadable or
non-SQLite files are reported as collection problems.

Not present in this collection (and therefore not parsed here): Windows event
logs (``*.evtx``) and registry hives (``NTUSER.DAT``/``SAM``). Parsers for those
would slot in alongside :func:`parse_artifacts` and require extra libraries
(``python-evtx``, ``python-registry``); see the README.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import sqlite3
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

from .loaders import CollectionProblem
from .normalizers import normalize_path

# SQLite file header magic (first 16 bytes of any SQLite 3 database).
_SQLITE_MAGIC = b"SQLite format 3\x00"

# Chromium timestamps are microseconds since 1601-01-01 UTC (the Windows epoch).
_CHROME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)

_USER_RE = re.compile(r"[\\/]Users[\\/]([^\\/]+)", re.IGNORECASE)

# Evidence types emitted by this module (used downstream for idempotent reruns).
ARTIFACT_EVIDENCE_TYPES = {"browser_history", "browser_download"}


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


def _record_id(source_name: str, table: str, row_id: Any) -> str:
    """Deterministic record id for an artifact row."""
    digest = hashlib.sha1(f"{source_name}:{table}:{row_id}".encode()).hexdigest()[:12]
    return f"{Path(source_name).name}:{table}:{row_id}:{digest}"


def _query(conn: sqlite3.Connection, sql: str) -> List[tuple]:
    """Run a query, returning ``[]`` if the table/columns are absent."""
    try:
        return conn.execute(sql).fetchall()
    except sqlite3.Error:
        return []


def _parse_history_db(
    path: Path, source_name: str
) -> Tuple[List[Dict[str, Any]], List[CollectionProblem]]:
    """Parse one History database into browsing + download records."""
    records: List[Dict[str, Any]] = []
    problems: List[CollectionProblem] = []
    username = _username_from_path(path)

    # Copy to a temp file so a live/WAL database can be read safely. Close the
    # descriptor mkstemp opens, otherwise Windows keeps the file locked.
    fd, tmp_name = tempfile.mkstemp(suffix=".sqlite")
    os.close(fd)
    tmp = Path(tmp_name)
    try:
        shutil.copy(path, tmp)
        conn = sqlite3.connect(f"file:{tmp}?mode=ro&immutable=1", uri=True)
    except (OSError, sqlite3.Error) as exc:
        problems.append(CollectionProblem(source_name, "unreadable_artifact", str(exc)))
        tmp.unlink(missing_ok=True)
        return records, problems

    try:
        for row in _query(
            conn,
            "SELECT id, url, title, visit_count, typed_count, last_visit_time "
            "FROM urls",
        ):
            row_id, url, title, visit_count, typed_count, last_visit = row
            if not url:
                continue
            records.append(
                {
                    "record_id": _record_id(source_name, "urls", row_id),
                    "source_file": source_name,
                    "evidence_type": "browser_history",
                    "timestamp": _chrome_time_to_iso(last_visit),
                    "identifiers": {
                        k: v
                        for k, v in {"url": url, "username": username}.items()
                        if v
                    },
                    "path": normalize_path(None),
                    "original_data": {
                        "url": url,
                        "title": title,
                        "visit_count": visit_count,
                        "typed_count": typed_count,
                        "last_visit_utc": _chrome_time_to_iso(last_visit),
                    },
                }
            )

        for row in _query(
            conn,
            "SELECT d.id, dc.url, d.target_path, d.start_time, d.end_time, "
            "d.received_bytes, d.total_bytes, d.state "
            "FROM downloads d "
            "LEFT JOIN downloads_url_chains dc ON d.id = dc.id",
        ):
            (row_id, url, target_path, start, end, received, total, state) = row
            records.append(
                {
                    "record_id": _record_id(source_name, "downloads", row_id),
                    "source_file": source_name,
                    "evidence_type": "browser_download",
                    "timestamp": _chrome_time_to_iso(start),
                    "identifiers": {
                        k: v
                        for k, v in {
                            "url": url,
                            "username": username,
                            "file_path": target_path,
                        }.items()
                        if v
                    },
                    "path": normalize_path(target_path),
                    "original_data": {
                        "url": url,
                        "target_path": target_path,
                        "start_time_utc": _chrome_time_to_iso(start),
                        "end_time_utc": _chrome_time_to_iso(end),
                        "received_bytes": received,
                        "total_bytes": total,
                        "state": state,
                    },
                }
            )
    finally:
        conn.close()
        tmp.unlink(missing_ok=True)

    if not records:
        problems.append(
            CollectionProblem(source_name, "no_records", "no urls/downloads rows")
        )
    return records, problems


def _relative_name(path: Path, root: Path) -> str:
    """Stable, POSIX-style identifier for a source artifact."""
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.name


def parse_artifacts(raw_dir: Path) -> Dict[str, Any]:
    """Parse all supported binary artifacts under ``raw_dir``.

    Returns ``{"records": [...], "problems": [...], "stats": {...}}`` where the
    records use the Phase 1 normalized schema.
    """
    all_records: List[Dict[str, Any]] = []
    all_problems: List[CollectionProblem] = []

    history_dbs = discover_browser_history(raw_dir)
    for path in history_dbs:
        source_name = _relative_name(path, raw_dir)
        records, problems = _parse_history_db(path, source_name)
        all_records.extend(records)
        all_problems.extend(problems)

    stats = {
        "history_databases": len(history_dbs),
        "artifact_records": len(all_records),
        "browser_history_records": sum(
            1 for r in all_records if r["evidence_type"] == "browser_history"
        ),
        "browser_download_records": sum(
            1 for r in all_records if r["evidence_type"] == "browser_download"
        ),
    }
    return {"records": all_records, "problems": all_problems, "stats": stats}
