"""Windows Shell Link (``.lnk``) parsing, standard library only.

Shell links are one of the few artifacts in this collection that record *user
interaction* with a file: the target path, the volume it lived on, and the
target's own MACB timestamps as they were when the shortcut was last written.
That makes them the main evidence for "what did the user open, and when".

The parser implements just enough of MS-SHLLINK to recover the fields an
investigation needs; anything it cannot decode is reported as a collection
problem rather than raised, so one malformed shortcut never stops a run.
"""

from __future__ import annotations

import struct
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .loaders import CollectionProblem

# Every shell link starts with a 0x4C-byte header followed by this class id.
_HEADER_SIZE = 0x4C
_LINK_CLSID = bytes(
    [0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
     0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46]
)

# LinkFlags bits we act on (MS-SHLLINK 2.1.1).
_HAS_TARGET_ID_LIST = 0x00000001
_HAS_LINK_INFO = 0x00000002
_HAS_NAME = 0x00000004
_HAS_RELATIVE_PATH = 0x00000008
_HAS_WORKING_DIR = 0x00000010
_HAS_ARGUMENTS = 0x00000020
_HAS_ICON_LOCATION = 0x00000040
_IS_UNICODE = 0x00000080

# StringData blocks, in the fixed order they appear on disk.
_STRING_FIELDS: Tuple[Tuple[int, str], ...] = (
    (_HAS_NAME, "name"),
    (_HAS_RELATIVE_PATH, "relative_path"),
    (_HAS_WORKING_DIR, "working_directory"),
    (_HAS_ARGUMENTS, "command_line_arguments"),
    (_HAS_ICON_LOCATION, "icon_location"),
)

# FILETIME is 100-nanosecond intervals since 1601-01-01 UTC.
_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def _filetime_to_iso(value: int) -> Optional[str]:
    """Convert a Windows FILETIME to a UTC ISO-8601 string (or ``None``)."""
    if value <= 0:
        return None
    try:
        dt = _FILETIME_EPOCH + timedelta(microseconds=value // 10)
    except (OverflowError, ValueError):
        return None
    return dt.isoformat().replace("+00:00", "Z")


def _read_string_data(blob: bytes, offset: int, unicode_: bool) -> Tuple[Optional[str], int]:
    """Read one counted StringData block, returning its text and new offset."""
    if offset + 2 > len(blob):
        return None, offset
    (count,) = struct.unpack_from("<H", blob, offset)
    offset += 2
    width = 2 if unicode_ else 1
    size = count * width
    if offset + size > len(blob):
        return None, len(blob)
    raw = blob[offset : offset + size]
    offset += size
    text = raw.decode("utf-16-le" if unicode_ else "latin-1", errors="replace")
    return text.rstrip("\x00") or None, offset


def _read_link_info(blob: bytes, offset: int) -> Tuple[Dict[str, Any], int]:
    """Read the LinkInfo structure, returning the local path and new offset."""
    info: Dict[str, Any] = {}
    if offset + 8 > len(blob):
        return info, offset
    (size, header_size) = struct.unpack_from("<II", blob, offset)
    if size < 8 or offset + size > len(blob):
        return info, min(offset + max(size, 8), len(blob))

    section = blob[offset : offset + size]
    try:
        (_, _, flags, volume_off, local_off, network_off, suffix_off) = struct.unpack_from(
            "<IIIIIII", section, 0
        )
    except struct.error:
        return info, offset + size

    def _cstring(start: int, encoding: str) -> Optional[str]:
        """Read a NUL-terminated string at ``start`` inside the LinkInfo blob."""
        if start <= 0 or start >= len(section):
            return None
        step = 2 if encoding.startswith("utf-16") else 1
        end = start
        while end + step <= len(section):
            if section[end : end + step] == b"\x00" * step:
                break
            end += step
        return section[start:end].decode(encoding, errors="replace") or None

    local_path = _cstring(local_off, "latin-1")
    suffix = _cstring(suffix_off, "latin-1")

    # A header of 0x24+ carries additional Unicode offsets that supersede the
    # code-page strings above.
    if header_size >= 0x24:
        try:
            (local_uni_off, suffix_uni_off) = struct.unpack_from("<II", section, 28)
        except struct.error:
            local_uni_off = suffix_uni_off = 0
        local_path = _cstring(local_uni_off, "utf-16-le") or local_path
        suffix = _cstring(suffix_uni_off, "utf-16-le") or suffix

    if local_path:
        info["local_base_path"] = local_path
    if suffix:
        info["common_path_suffix"] = suffix
    if local_path or suffix:
        info["target_path"] = (local_path or "") + (suffix or "")
    if volume_off or network_off:
        info["link_info_flags"] = flags
    return info, offset + size


def parse_lnk_bytes(blob: bytes) -> Optional[Dict[str, Any]]:
    """Parse shell-link bytes into a flat field dict, or ``None`` if not a LNK."""
    if len(blob) < _HEADER_SIZE:
        return None
    (header_size,) = struct.unpack_from("<I", blob, 0)
    if header_size != _HEADER_SIZE or blob[4:20] != _LINK_CLSID:
        return None

    (flags, file_attributes) = struct.unpack_from("<II", blob, 20)
    (created, accessed, written) = struct.unpack_from("<QQQ", blob, 28)
    (file_size, icon_index, show_command) = struct.unpack_from("<Iii", blob, 52)

    fields: Dict[str, Any] = {
        "target_created": _filetime_to_iso(created),
        "target_accessed": _filetime_to_iso(accessed),
        "target_modified": _filetime_to_iso(written),
        "target_size": file_size,
        "target_file_attributes": file_attributes,
        "show_command": show_command,
        "icon_index": icon_index,
    }

    offset = _HEADER_SIZE
    if flags & _HAS_TARGET_ID_LIST:
        if offset + 2 > len(blob):
            return fields
        (idlist_size,) = struct.unpack_from("<H", blob, offset)
        offset += 2 + idlist_size

    if flags & _HAS_LINK_INFO:
        link_info, offset = _read_link_info(blob, offset)
        fields.update(link_info)

    unicode_ = bool(flags & _IS_UNICODE)
    for bit, name in _STRING_FIELDS:
        if flags & bit:
            value, offset = _read_string_data(blob, offset, unicode_)
            if value:
                fields[name] = value

    # Prefer the LinkInfo path; fall back to the relative path when absent.
    if not fields.get("target_path") and fields.get("relative_path"):
        fields["target_path"] = fields["relative_path"]

    return {k: v for k, v in fields.items() if v not in (None, "", 0)}


def parse_lnk_file(path: Path) -> Tuple[Optional[Dict[str, Any]], Optional[CollectionProblem]]:
    """Parse one ``.lnk`` file from disk, reporting problems instead of raising."""
    try:
        blob = path.read_bytes()
    except OSError as exc:
        return None, CollectionProblem(path.name, "unreadable_file", str(exc))

    try:
        fields = parse_lnk_bytes(blob)
    except (struct.error, ValueError, UnicodeDecodeError) as exc:
        return None, CollectionProblem(path.name, "malformed_lnk", str(exc))

    if fields is None:
        return None, CollectionProblem(path.name, "not_a_shell_link", "bad LNK header")
    return fields, None


def collect_lnk_records(files: List[Path], root: Path) -> Tuple[List[Dict[str, Any]], List[CollectionProblem]]:
    """Parse every shell link in ``files`` into raw payload dicts."""
    records: List[Dict[str, Any]] = []
    problems: List[CollectionProblem] = []
    for path in files:
        fields, problem = parse_lnk_file(path)
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
