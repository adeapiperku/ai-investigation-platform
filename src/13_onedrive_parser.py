"""OneDrive sync-log (``.odl`` / ``.odlgz`` / ``.aodl``) recovery.

OneDrive writes its sync telemetry to ODL logs under
``AppData/Local/Microsoft/OneDrive/logs``. They are the only artifact in this
collection that records **what the cloud pushed down to the endpoint**, which is
what the cloud-sync questions turn on.

Fully decoding ODL requires the per-build ``ObfuscationStringMap`` that Microsoft
ships with the client — it is not present in this collection. So this module
does the part that is sound without it: it recovers the readable payload
(inflating the gzip members that newer builds use) and extracts the URLs, file
paths and filenames it contains, tagged with the log's own timestamp. Anything
that cannot be inflated is reported as a collection problem, never raised.
"""

from __future__ import annotations

import re
import zlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .loaders import CollectionProblem

# ODL files start with this signature; the header is 0x100 bytes.
_ODL_SIGNATURE = b"EBFGONED"
_HEADER_SIZE = 0x100

# gzip member magic: \x1f\x8b, deflate method.
_GZIP_MAGIC = b"\x1f\x8b\x08"

# OneDrive names its logs <Component>-<YYYY-MM-DD>.<HHMM>.<pid>.<seq>.odl
_LOG_NAME_RE = re.compile(
    r"^(?P<component>[A-Za-z]+)-(?P<date>\d{4}-\d{2}-\d{2})\.(?P<time>\d{4})\."
    r"(?P<pid>\d+)\.(?P<seq>\d+)\."
)

_URL_RE = re.compile(r"https?://[^\s\"'<>\\|)\]}]{4,}")
_WIN_PATH_RE = re.compile(r"[A-Za-z]:\\\\?[^\s\"'<>|*?]{3,}")
_FILENAME_RE = re.compile(r"\b[\w.\-]{1,64}\.(?:exe|dll|ps1|bat|cmd|lnk|zip|docx?|xlsx?|pdf|js|vbs|scr|url)\b", re.IGNORECASE)

# Printable-string extraction thresholds.
_MIN_STRING_LEN = 6
_ASCII_RE = re.compile(rb"[\x20-\x7e]{%d,}" % _MIN_STRING_LEN)
_UTF16_RE = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % _MIN_STRING_LEN)

# Cap how much of a single log we retain, so one chatty log cannot dominate.
_MAX_STRINGS_PER_LOG = 400


def _timestamp_from_name(name: str) -> Optional[str]:
    """Derive the log's UTC start time from the OneDrive log filename."""
    match = _LOG_NAME_RE.match(name)
    if not match:
        return None
    try:
        dt = datetime.strptime(
            f"{match.group('date')} {match.group('time')}", "%Y-%m-%d %H%M"
        ).replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    return dt.isoformat().replace("+00:00", "Z")


def _inflate_all(blob: bytes) -> bytes:
    """Inflate every gzip member found in ``blob`` and append the plain regions.

    Newer OneDrive builds compress each data block separately, so a log holds
    many independent gzip members rather than one stream. Members that fail to
    inflate are skipped: a truncated tail is normal in a live-collected log.
    """
    chunks: List[bytes] = []
    position = 0
    found_any = False

    while True:
        index = blob.find(_GZIP_MAGIC, position)
        if index == -1:
            break
        found_any = True
        decompressor = zlib.decompressobj(wbits=16 + zlib.MAX_WBITS)
        try:
            chunks.append(decompressor.decompress(blob[index:]))
        except zlib.error:
            position = index + len(_GZIP_MAGIC)
            continue
        consumed = len(blob) - index - len(decompressor.unused_data)
        position = index + max(consumed, len(_GZIP_MAGIC))

    if not found_any:
        return blob
    # Keep the uncompressed header/context regions too; they carry the version.
    chunks.append(blob[:_HEADER_SIZE])
    return b"\n".join(chunks)


def _extract_strings(blob: bytes) -> List[str]:
    """Recover ASCII and UTF-16LE printable strings from a binary blob."""
    seen: Dict[str, None] = {}
    for match in _ASCII_RE.finditer(blob):
        seen.setdefault(match.group().decode("ascii", errors="replace"), None)
    for match in _UTF16_RE.finditer(blob):
        seen.setdefault(match.group().decode("utf-16-le", errors="replace"), None)
    return list(seen)


def _onedrive_version(blob: bytes) -> Optional[str]:
    """Read the client version string from the ODL header, when present."""
    if len(blob) < _HEADER_SIZE or not blob.startswith(_ODL_SIGNATURE):
        return None
    raw = blob[0x18:0x58].decode("utf-16-le", errors="replace").split("\x00")[0]
    return raw.strip() or None


def parse_odl_file(path: Path) -> Tuple[Optional[Dict[str, Any]], Optional[CollectionProblem]]:
    """Recover one ODL log into a flat field dict."""
    try:
        blob = path.read_bytes()
    except OSError as exc:
        return None, CollectionProblem(path.name, "unreadable_file", str(exc))

    if not blob:
        return None, CollectionProblem(path.name, "zero_byte_file", "file is empty")

    version = _onedrive_version(blob)
    try:
        payload = _inflate_all(blob)
    except (zlib.error, MemoryError) as exc:
        return None, CollectionProblem(path.name, "odl_inflate_failed", str(exc))

    strings = _extract_strings(payload)
    urls = sorted({m.group() for s in strings for m in _URL_RE.finditer(s)})
    paths = sorted({m.group() for s in strings for m in _WIN_PATH_RE.finditer(s)})
    filenames = sorted({m.group() for s in strings for m in _FILENAME_RE.finditer(s)})

    name_match = _LOG_NAME_RE.match(path.name)
    fields: Dict[str, Any] = {
        "log_component": name_match.group("component") if name_match else None,
        "log_timestamp": _timestamp_from_name(path.name),
        "onedrive_version": version,
        "compressed": _GZIP_MAGIC in blob,
        "urls": urls,
        "file_paths": paths,
        "referenced_filenames": filenames,
        "recovered_strings": strings[:_MAX_STRINGS_PER_LOG],
        "recovered_string_count": len(strings),
    }
    return {k: v for k, v in fields.items() if v not in (None, [], "")}, None


def collect_onedrive_records(
    files: List[Path], root: Path
) -> Tuple[List[Dict[str, Any]], List[CollectionProblem]]:
    """Recover every ODL log in ``files`` into raw payload dicts."""
    records: List[Dict[str, Any]] = []
    problems: List[CollectionProblem] = []
    for path in files:
        fields, problem = parse_odl_file(path)
        if problem is not None:
            problems.append(problem)
            continue
        if not fields:
            continue
        records.append({**fields, "_artifact_source": _relative(path, root)})
    return records, problems


def _relative(path: Path, root: Path) -> str:
    """Return a POSIX-style path relative to the raw data root."""
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.name
