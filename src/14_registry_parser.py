"""Minimal Windows registry (``regf``) hive reader, standard library only.

Only the user hives (``NTUSER.DAT``, ``UsrClass.dat``) were collected here, and
only a handful of their keys carry investigative weight — session/logon context,
program execution, and recently opened documents. So rather than exploding an
entire hive into the dataset, this module walks the hive structure and emits one
normalized record per **key of interest**, carrying that key's last-write time
and decoded values.

Implements the subset of the format needed for that: the ``regf`` base block,
``nk``/``vk`` cells, and the ``lf``/``lh``/``li``/``ri`` subkey lists. Values
stored in ``db`` big-data cells are marked truncated rather than reassembled.
Corrupt cells are reported as collection problems, never raised.
"""

from __future__ import annotations

import codecs
import struct
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

from .loaders import CollectionProblem

_REGF_SIGNATURE = b"regf"
_HIVE_BINS_START = 0x1000

# Value data types we decode (winnt.h REG_*).
_REG_SZ, _REG_EXPAND_SZ, _REG_BINARY = 1, 2, 3
_REG_DWORD, _REG_DWORD_BE, _REG_MULTI_SZ, _REG_QWORD = 4, 5, 7, 11

# Values whose data lives inline in the offset field carry this size bit.
_INLINE_DATA_BIT = 0x80000000

_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)

# Keys worth extracting, as case-insensitive paths below the hive root.
# Each entry is (path, why-it-matters tag).
KEYS_OF_INTEREST: Tuple[Tuple[str, str], ...] = (
    ("Volatile Environment", "logon_session"),
    ("Software/Microsoft/Windows/CurrentVersion/Explorer/UserAssist", "program_execution"),
    ("Software/Microsoft/Windows/CurrentVersion/Explorer/RecentDocs", "file_access"),
    ("Software/Microsoft/Windows/CurrentVersion/Explorer/RunMRU", "user_command"),
    ("Software/Microsoft/Windows/CurrentVersion/Explorer/TypedPaths", "user_navigation"),
    ("Software/Microsoft/Windows/CurrentVersion/Explorer/ComDlg32", "file_access"),
    ("Software/Microsoft/Windows/CurrentVersion/Run", "persistence"),
    ("Software/Microsoft/Windows/CurrentVersion/RunOnce", "persistence"),
    ("Software/Microsoft/Internet Explorer/TypedURLs", "user_navigation"),
    ("Software/Microsoft/Office", "file_access"),
    ("Software/Microsoft/Terminal Server Client", "lateral_movement"),
    ("Software/SimonTatham/PuTTY", "lateral_movement"),
    ("Software/Microsoft/OneDrive", "cloud_sync"),
)

# UserAssist entry layout (Windows 7+): run count at 0x04, FILETIME at 0x3C.
_USERASSIST_ENTRY_SIZE = 72


def _filetime_to_iso(value: int) -> Optional[str]:
    """Convert a Windows FILETIME to a UTC ISO-8601 string (or ``None``)."""
    if value <= 0:
        return None
    try:
        return (_FILETIME_EPOCH + timedelta(microseconds=value // 10)).isoformat().replace(
            "+00:00", "Z"
        )
    except (OverflowError, ValueError):
        return None


class HiveError(Exception):
    """Raised internally when a hive cannot be walked; callers convert to problems."""


class Hive:
    """A memory-mapped-in-full registry hive, read-only."""

    def __init__(self, blob: bytes) -> None:
        if len(blob) < _HIVE_BINS_START or not blob.startswith(_REGF_SIGNATURE):
            raise HiveError("not a regf hive")
        self.blob = blob
        (self.last_written,) = struct.unpack_from("<Q", blob, 0x0C)
        (self.root_offset,) = struct.unpack_from("<I", blob, 0x24)

    def _cell(self, offset: int) -> bytes:
        """Return the payload of the cell at a hive-bins-relative ``offset``."""
        if offset in (0, 0xFFFFFFFF):
            raise HiveError("null cell offset")
        start = _HIVE_BINS_START + offset
        if start + 4 > len(self.blob):
            raise HiveError(f"cell offset {offset} out of range")
        (size,) = struct.unpack_from("<i", self.blob, start)
        length = abs(size)
        if length < 4 or start + length > len(self.blob):
            raise HiveError(f"bad cell size at {offset}")
        return self.blob[start + 4 : start + length]

    # ---------------------------------------------------------------- keys --

    def root(self) -> "Key":
        """Return the hive's root key."""
        return Key(self, self.root_offset)

    def find(self, path: str) -> Optional["Key"]:
        """Resolve a ``/``-separated key path below the root, case-insensitively."""
        node = self.root()
        for part in path.split("/"):
            if not part:
                continue
            node = node.subkey(part)
            if node is None:
                return None
        return node


class Key:
    """One ``nk`` cell: a registry key with its values and subkeys."""

    def __init__(self, hive: Hive, offset: int) -> None:
        self.hive = hive
        self.offset = offset
        data = hive._cell(offset)
        if data[:2] != b"nk":
            raise HiveError(f"expected nk cell at {offset}")
        self._data = data
        (self.flags,) = struct.unpack_from("<H", data, 2)
        (self.last_written,) = struct.unpack_from("<Q", data, 4)
        (self.subkey_count,) = struct.unpack_from("<I", data, 20)
        (self._subkeys_offset,) = struct.unpack_from("<I", data, 28)
        (self.value_count,) = struct.unpack_from("<I", data, 36)
        (self._values_offset,) = struct.unpack_from("<I", data, 40)
        (name_length,) = struct.unpack_from("<H", data, 72)
        raw_name = data[76 : 76 + name_length]
        # Flag 0x20 marks a compressed (latin-1) name; otherwise UTF-16LE.
        self.name = raw_name.decode(
            "latin-1" if self.flags & 0x20 else "utf-16-le", errors="replace"
        )

    @property
    def last_written_iso(self) -> Optional[str]:
        """The key's last-write time as UTC ISO-8601."""
        return _filetime_to_iso(self.last_written)

    def subkeys(self) -> Iterator["Key"]:
        """Yield every direct subkey."""
        if not self.subkey_count or self._subkeys_offset in (0, 0xFFFFFFFF):
            return
        for offset in self._subkey_offsets(self._subkeys_offset):
            try:
                yield Key(self.hive, offset)
            except (HiveError, struct.error):
                continue

    def _subkey_offsets(self, list_offset: int) -> List[int]:
        """Resolve an lf/lh/li/ri subkey list into concrete nk cell offsets."""
        try:
            data = self.hive._cell(list_offset)
        except HiveError:
            return []
        signature = data[:2]
        try:
            (count,) = struct.unpack_from("<H", data, 2)
        except struct.error:
            return []

        if signature in (b"lf", b"lh"):
            # Pairs of (nk offset, name hash).
            return [
                struct.unpack_from("<I", data, 4 + i * 8)[0]
                for i in range(count)
                if 4 + i * 8 + 4 <= len(data)
            ]
        if signature == b"li":
            return [
                struct.unpack_from("<I", data, 4 + i * 4)[0]
                for i in range(count)
                if 4 + i * 4 + 4 <= len(data)
            ]
        if signature == b"ri":
            # An index of further lists; flatten one level down.
            offsets: List[int] = []
            for i in range(count):
                if 4 + i * 4 + 4 > len(data):
                    break
                (sub,) = struct.unpack_from("<I", data, 4 + i * 4)
                offsets.extend(self._subkey_offsets(sub))
            return offsets
        return []

    def subkey(self, name: str) -> Optional["Key"]:
        """Return the direct subkey with ``name`` (case-insensitive), if any."""
        wanted = name.lower()
        for child in self.subkeys():
            if child.name.lower() == wanted:
                return child
        return None

    def values(self) -> Dict[str, Any]:
        """Decode every value under this key into a name -> value mapping."""
        if not self.value_count or self._values_offset in (0, 0xFFFFFFFF):
            return {}
        try:
            table = self.hive._cell(self._values_offset)
        except HiveError:
            return {}

        result: Dict[str, Any] = {}
        for index in range(self.value_count):
            if 4 * index + 4 > len(table):
                break
            (offset,) = struct.unpack_from("<I", table, 4 * index)
            try:
                name, value = self._read_value(offset)
            except (HiveError, struct.error, ValueError):
                continue
            result[name] = value
        return result

    def _read_value(self, offset: int) -> Tuple[str, Any]:
        """Decode one ``vk`` cell into a (name, value) pair."""
        data = self.hive._cell(offset)
        if data[:2] != b"vk":
            raise HiveError("expected vk cell")
        (name_length,) = struct.unpack_from("<H", data, 2)
        (data_size,) = struct.unpack_from("<I", data, 4)
        (data_offset,) = struct.unpack_from("<I", data, 8)
        (data_type,) = struct.unpack_from("<I", data, 12)
        (flags,) = struct.unpack_from("<H", data, 16)

        raw_name = data[20 : 20 + name_length]
        name = raw_name.decode(
            "latin-1" if flags & 0x0001 else "utf-16-le", errors="replace"
        ) or "(default)"

        inline = bool(data_size & _INLINE_DATA_BIT)
        size = data_size & ~_INLINE_DATA_BIT
        if inline:
            payload = struct.pack("<I", data_offset)[:size]
        else:
            if size > 16344:
                return name, {"_truncated": True, "_size": size, "_type": data_type}
            payload = self.hive._cell(data_offset)[:size]

        return name, _decode_value(payload, data_type)


def _decode_value(payload: bytes, data_type: int) -> Any:
    """Turn raw value bytes into a JSON-friendly Python value."""
    if data_type in (_REG_SZ, _REG_EXPAND_SZ):
        return payload.decode("utf-16-le", errors="replace").split("\x00")[0]
    if data_type == _REG_MULTI_SZ:
        text = payload.decode("utf-16-le", errors="replace")
        return [part for part in text.split("\x00") if part]
    if data_type == _REG_DWORD and len(payload) >= 4:
        return struct.unpack_from("<I", payload, 0)[0]
    if data_type == _REG_DWORD_BE and len(payload) >= 4:
        return struct.unpack_from(">I", payload, 0)[0]
    if data_type == _REG_QWORD and len(payload) >= 8:
        return struct.unpack_from("<Q", payload, 0)[0]
    if data_type == _REG_BINARY:
        return payload.hex()
    return payload.hex()


# ------------------------------------------------------------------ UserAssist


def _decode_userassist(key: Key) -> List[Dict[str, Any]]:
    """Decode UserAssist ``Count`` subkeys into execution records.

    Entry names are ROT13-encoded program paths; the binary value carries the
    run count and the last execution time.
    """
    entries: List[Dict[str, Any]] = []
    for guid_key in key.subkeys():
        count_key = guid_key.subkey("Count")
        if count_key is None:
            continue
        for name, value in count_key.values().items():
            if not isinstance(value, str):
                continue
            try:
                blob = bytes.fromhex(value)
            except ValueError:
                continue
            if len(blob) < _USERASSIST_ENTRY_SIZE:
                continue
            (run_count,) = struct.unpack_from("<I", blob, 4)
            (last_run,) = struct.unpack_from("<Q", blob, 60)
            entries.append(
                {
                    "program": codecs.decode(name, "rot_13"),
                    "run_count": run_count,
                    "last_run": _filetime_to_iso(last_run),
                    "guid": guid_key.name,
                }
            )
    return entries


# -------------------------------------------------------------- record output


def parse_hive_file(
    path: Path, root: Path
) -> Tuple[List[Dict[str, Any]], List[CollectionProblem]]:
    """Extract the keys of interest from one hive into raw payload dicts."""
    source = _relative(path, root)
    try:
        blob = path.read_bytes()
    except OSError as exc:
        return [], [CollectionProblem(source, "unreadable_file", str(exc))]

    try:
        hive = Hive(blob)
    except (HiveError, struct.error) as exc:
        return [], [CollectionProblem(source, "not_a_registry_hive", str(exc))]

    records: List[Dict[str, Any]] = [
        {
            "registry_key": "(hive root)",
            "significance": "hive_metadata",
            "hive_last_written": _filetime_to_iso(hive.last_written),
            "hive_file": path.name,
            "_artifact_source": source,
        }
    ]
    problems: List[CollectionProblem] = []

    for key_path, significance in KEYS_OF_INTEREST:
        try:
            key = hive.find(key_path)
        except (HiveError, struct.error) as exc:
            problems.append(
                CollectionProblem(source, "registry_walk_failed", f"{key_path}: {exc}")
            )
            continue
        if key is None:
            continue

        record: Dict[str, Any] = {
            "registry_key": key_path,
            "significance": significance,
            "key_last_written": key.last_written_iso,
            "hive_file": path.name,
            "_artifact_source": source,
        }
        try:
            values = key.values()
        except (HiveError, struct.error):
            values = {}
        if values:
            record["values"] = values

        if significance == "program_execution":
            try:
                entries = _decode_userassist(key)
            except (HiveError, struct.error):
                entries = []
            if entries:
                record["userassist_entries"] = entries
        else:
            subkeys = [
                {"name": child.name, "last_written": child.last_written_iso}
                for child in key.subkeys()
            ]
            if subkeys:
                record["subkeys"] = subkeys[:200]

        records.append(record)

    return records, problems


def collect_registry_records(
    files: List[Path], root: Path
) -> Tuple[List[Dict[str, Any]], List[CollectionProblem]]:
    """Extract keys of interest from every hive in ``files``."""
    records: List[Dict[str, Any]] = []
    problems: List[CollectionProblem] = []
    for path in files:
        hive_records, hive_problems = parse_hive_file(path, root)
        records.extend(hive_records)
        problems.extend(hive_problems)
    return records, problems


def _relative(path: Path, root: Path) -> str:
    """Return a POSIX-style path relative to the raw data root."""
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.name
