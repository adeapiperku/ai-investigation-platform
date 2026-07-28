"""Building the Azure AI Foundry upload bundle.

A Foundry agent's file-search index is not a database — every uploaded byte is
chunked and embedded, so shipping 25 000 rows of ``C:\\Windows\\WinSxS`` metadata
buys nothing and drowns the records that matter. This module produces the
upload set: the small datasets whole, the bulk datasets reduced to the records
an investigator would actually reach for, plus a manifest telling the agent what
each file contains and which questions it bears on.

The reduction is stated, not hidden: every filtered file records how many
records were dropped and by what rule, so nothing looks like complete evidence
when it is not.
"""

from __future__ import annotations

import csv
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Tuple

from .dataset_registry import DATASETS_BY_NAME

# Directory tokens that make a file worth keeping: user-controlled or
# malware-favoured locations, plus the cloud-sync roots.
_RELEVANT_DIR_TOKENS = (
    "/users/",
    "/programdata/",
    "/temp/",
    "/tmp/",
    "/downloads/",
    "/desktop/",
    "/documents/",
    "/onedrive/",
    "/appdata/roaming/",
    "/appdata/local/temp/",
    "/startup/",
    "/public/",
    "/perflogs/",
)

# Extensions that carry execution, delivery or credential meaning.
_RELEVANT_EXTENSIONS = {
    "exe", "dll", "sys", "scr", "com", "pif", "cpl", "msi", "msix",
    "ps1", "psm1", "bat", "cmd", "vbs", "vbe", "js", "jse", "wsf", "hta",
    "zip", "rar", "7z", "gz", "tar", "iso", "img", "cab",
    "doc", "docx", "docm", "xls", "xlsx", "xlsm", "rtf", "pdf", "one",
    "lnk", "url", "sqlite", "db", "dat", "odl", "odlgz", "log",
    "txt", "csv", "json", "xml", "config", "ini", "kdbx", "pem", "key", "ppk",
}

# System paths that are noise even when they match the rules above.
_NOISE_RE = re.compile(
    r"/(winsxs|servicing|assembly|inf|catroot2?|driverstore|softwaredistribution|"
    r"windowsapps|systemapps|fonts|globalization|policydefinitions|"
    r"microsoft\.net/assembly)/",
    re.IGNORECASE,
)

# Backstop ceiling per filtered dataset, so a pathological source cannot
# dominate the index. Set well above the current collection's relevant counts
# (~16k) — truncation loses evidence, so the relevance rule does the real work
# and this only catches runaway inputs.
MAX_FILTERED_RECORDS = 20000

# Foundry file-search indexes text; keep individual files comfortably small.
SOFT_SIZE_LIMIT_MB = 20.0


def _is_relevant(record: Dict[str, Any]) -> bool:
    """Decide whether a bulk-dataset record is worth putting in the index."""
    path = (record.get("path") or {}).get("full_path") or ""
    posix = path.replace("\\", "/").lower()
    if _NOISE_RE.search(posix):
        return False

    extension = ((record.get("path") or {}).get("extension") or "").lower()
    in_relevant_dir = any(token in posix for token in _RELEVANT_DIR_TOKENS)
    if in_relevant_dir and (not extension or extension in _RELEVANT_EXTENSIONS):
        return True

    identifiers = record.get("identifiers") or {}
    # Anything carrying a network indicator is always worth keeping.
    return bool(identifiers.get("url") or identifiers.get("ip") or identifiers.get("cve"))


def reduce_dataset(document: Dict[str, Any], mode: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Return an upload-ready copy of a dataset plus a note on what was cut."""
    records: List[Dict[str, Any]] = document.get("records", [])
    if mode != "filtered":
        return document, {"filtered": False, "records_kept": len(records)}

    kept = [record for record in records if _is_relevant(record)]
    truncated = len(kept) > MAX_FILTERED_RECORDS
    if truncated:
        # Keep the most recent activity: an incident lives at the end of the
        # timeline, and undated records are least useful to a retrieval index.
        kept.sort(key=lambda r: (r.get("timestamp") or "", r.get("record_id", "")))
        kept = kept[-MAX_FILTERED_RECORDS:]

    note = {
        "filtered": True,
        "rule": (
            "kept records under user/ProgramData/Temp/Downloads/OneDrive paths with "
            "an execution-, delivery- or credential-relevant extension, plus every "
            "record carrying a URL, IP or CVE; dropped Windows servicing noise"
        ),
        "records_in_full_dataset": len(records),
        "records_kept": len(kept),
        "records_dropped": len(records) - len(kept),
        "truncated_to_most_recent": truncated,
    }

    reduced = dict(document)
    reduced["records"] = kept
    reduced["dataset"] = {**document.get("dataset", {}), "foundry_reduction": note}
    return reduced, note


def build_bundle(normalized_dir: Path, out_dir: Path) -> Dict[str, Any]:
    """Write the Foundry upload set from the per-dataset normalized files.

    Returns a manifest describing every file written, its size and its reduction.
    """
    from .normalized_loader import DATASET_SUFFIX, dataset_files, load_dataset

    out_dir.mkdir(parents=True, exist_ok=True)
    entries: List[Dict[str, Any]] = []

    for path in dataset_files(normalized_dir):
        name = path.name[: -len(DATASET_SUFFIX)]
        spec = DATASETS_BY_NAME.get(name)
        mode = spec.foundry if spec else "full"
        if mode == "skip":
            continue

        document = load_dataset(path)
        reduced, note = reduce_dataset(document, mode)

        target = out_dir / f"{name}.json"
        with target.open("w", encoding="utf-8") as handle:
            json.dump(reduced, handle, ensure_ascii=False, default=str)

        size_mb = target.stat().st_size / (1024 * 1024)
        entries.append(
            {
                "file": target.name,
                "dataset": name,
                "evidence_type": reduced.get("dataset", {}).get("evidence_type"),
                "description": reduced.get("dataset", {}).get("description"),
                "answers_questions": reduced.get("dataset", {}).get("answers_questions", []),
                "records": len(reduced.get("records", [])),
                "size_mb": round(size_mb, 2),
                "over_soft_limit": size_mb > SOFT_SIZE_LIMIT_MB,
                "reduction": note,
            }
        )

    manifest = {
        "purpose": (
            "Upload set for an Azure AI Foundry agent using the file_search tool. "
            "Each file is one normalized forensic dataset sharing the same record "
            "schema: record_id, dataset, source_file, evidence_type, timestamp "
            "(UTC ISO-8601), identifiers, path, original_data."
        ),
        "record_schema": [
            "record_id", "dataset", "source_file", "evidence_type",
            "timestamp", "identifiers", "path", "original_data",
        ],
        "grounding_rule": (
            "Every answer must cite the record_id and dataset it came from. If no "
            "record supports an answer, reply 'insufficient evidence'."
        ),
        "total_files": len(entries),
        "total_size_mb": round(sum(e["size_mb"] for e in entries), 2),
        "files": entries,
    }

    with (out_dir / "_manifest.json").open("w", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2, ensure_ascii=False)

    return manifest


# --------------------------------------------------------------------------- #
# CSV bundle, for the code-interpreter tool
# --------------------------------------------------------------------------- #

# Envelope columns every CSV carries, in this order.
_BASE_COLUMNS: Tuple[str, ...] = (
    "record_id",
    "dataset",
    "provenance",
    "evidence_type",
    "timestamp",
    "source_file",
)

# Identifier and path sub-fields worth their own column.
_ID_COLUMNS: Tuple[str, ...] = (
    "username", "hostname", "url", "ip", "cve", "hash", "file_path", "application",
)
_PATH_COLUMNS: Tuple[str, ...] = ("full_path", "directory", "filename", "extension")

# original_data keys skipped: they duplicate a column already emitted.
_REDUNDANT_PAYLOAD_KEYS = {"username", "url", "_artifact_source"}


def _flatten(record: Dict[str, Any]) -> Dict[str, Any]:
    """Flatten one normalized record into a single CSV row.

    Every column is written in full. Redundancy is removed at the *column*
    level afterwards (see :func:`_alias_columns` and :func:`_constant_columns`),
    never by blanking individual cells — a blank cell must always mean "absent",
    so that a reader can trust an empty MACB field rather than wonder whether it
    was deduplicated away. Nested values are JSON-encoded rather than dropped.
    """
    row: Dict[str, Any] = {key: record.get(key) for key in _BASE_COLUMNS}

    identifiers = record.get("identifiers") or {}
    for key in _ID_COLUMNS:
        if identifiers.get(key) is not None:
            row[f"id_{key}"] = identifiers[key]

    path = record.get("path") or {}
    for key in _PATH_COLUMNS:
        if path.get(key) is not None:
            row[f"path_{key}"] = path[key]

    for key, value in (record.get("original_data") or {}).items():
        if key in _REDUNDANT_PAYLOAD_KEYS:
            continue
        if isinstance(value, (dict, list)):
            row[key] = json.dumps(value, ensure_ascii=False, default=str)
        elif value is not None:
            row[key] = value
    return row


def _alias_columns(rows: List[Dict[str, Any]], columns: List[str]) -> Dict[str, str]:
    """Find payload columns that duplicate an envelope column on every row.

    A forensic record repeats itself: the same path arrives as
    ``identifiers.file_path``, as ``path.full_path`` and again as the payload's
    own ``SourceFile``. Where a column is an exact duplicate of an earlier one
    across the whole dataset, it is dropped and recorded in the manifest as an
    alias — so the information survives, one line instead of 26 000 rows.

    A column is only aliased when it matches on *every* row. Any divergence,
    however small, keeps the column: a `Modified` that usually equals `Created`
    but differs once is exactly the row an investigator is looking for.
    """
    aliases: Dict[str, str] = {}
    for index, column in enumerate(columns):
        if column in _BASE_COLUMNS:
            continue
        for earlier in columns[:index]:
            if earlier == "record_id" or earlier in aliases:
                continue
            if all(
                str(row.get(column)) == str(row.get(earlier)) for row in rows
            ):
                aliases[column] = earlier
                break
    return aliases


def _constant_columns(rows: List[Dict[str, Any]], columns: List[str]) -> Dict[str, Any]:
    """Find columns holding one identical value across every row.

    A column that never varies carries no information per row. It is recorded
    once in the manifest instead of 26 000 times in the file.
    """
    if len(rows) < 2:
        return {}
    constant: Dict[str, Any] = {}
    for column in columns:
        if column == "record_id":
            continue
        values = {str(row.get(column)) for row in rows}
        if len(values) == 1:
            value = rows[0].get(column)
            if value not in (None, ""):
                constant[column] = value
    return constant


def write_dataset_csv(
    document: Dict[str, Any], target: Path
) -> Tuple[int, Dict[str, Any], Dict[str, str]]:
    """Write one dataset as CSV, returning (rows, constant columns, aliases).

    Columns are the union of every row's keys, so a dataset keeps its own
    natural shape instead of being forced into a shared wide schema.
    """
    rows = [_flatten(record) for record in document.get("records", [])]

    columns: List[str] = list(_BASE_COLUMNS)
    seen = set(columns)
    for row in rows:
        for key in row:
            if key not in seen:
                seen.add(key)
                columns.append(key)

    constant = _constant_columns(rows, columns)
    aliases = _alias_columns(rows, columns) if rows else {}
    dropped = set(constant) | set(aliases)
    columns = [column for column in columns if column not in dropped]

    # newline="" is required on Windows or csv writes blank lines between rows.
    with target.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    return len(rows), constant, aliases


def build_csv_bundle(normalized_dir: Path, out_dir: Path) -> Dict[str, Any]:
    """Write the code-interpreter upload set: every dataset as CSV, unreduced.

    Code interpreter reads files rather than embedding them, so there is no
    reason to filter here — these are the complete datasets.
    """
    from .normalized_loader import DATASET_SUFFIX, dataset_files, load_dataset

    out_dir.mkdir(parents=True, exist_ok=True)
    entries: List[Dict[str, Any]] = []

    for path in dataset_files(normalized_dir):
        name = path.name[: -len(DATASET_SUFFIX)]
        spec = DATASETS_BY_NAME.get(name)
        document = load_dataset(path)

        target = out_dir / f"{name}.csv"
        row_count, constant, aliases = write_dataset_csv(document, target)
        size_mb = target.stat().st_size / (1024 * 1024)

        entries.append(
            {
                "file": target.name,
                "dataset": name,
                "evidence_type": document.get("dataset", {}).get("evidence_type"),
                "description": document.get("dataset", {}).get("description"),
                # Derived datasets are not in the catalogue; they carry their
                # own question mapping in the document itself.
                "answers_questions": (
                    list(spec.answers_questions)
                    if spec
                    else document.get("dataset", {}).get("answers_questions", [])
                ),
                "derived": document.get("dataset", {}).get("derived", False),
                "records": row_count,
                "size_mb": round(size_mb, 2),
                "complete": True,
                # Columns identical on every row, omitted from the CSV to save
                # space. They still apply to every record in the file.
                "constant_columns": constant,
                # Columns that duplicated another column on every single row,
                # omitted. Read the named column instead.
                "aliased_columns": aliases,
            }
        )

    manifest = {
        "purpose": (
            "Upload set for an Azure AI Foundry agent using the code_interpreter "
            "tool. Each CSV is one complete normalized forensic dataset - no "
            "records were filtered out. Load with pandas.read_csv."
        ),
        "shared_columns": list(_BASE_COLUMNS),
        "column_conventions": {
            "id_*": "correlation identifiers (username, url, ip, cve, hash, ...)",
            "path_*": "decomposed file path of the record's subject",
            "other columns": (
                "the dataset's own payload fields; nested values are JSON-encoded "
                "strings, decode with json.loads"
            ),
            "blank cells": (
                "a blank cell means the field is ABSENT for that record. Cells are "
                "never blanked for deduplication - trust an empty value."
            ),
            "constant_columns": (
                "per-file in this manifest: columns whose value is identical on "
                "every row, omitted from the CSV. They still apply to every record."
            ),
            "aliased_columns": (
                "per-file in this manifest: {dropped_column: equivalent_column}. "
                "The dropped column duplicated the named one on every row - read "
                "the named column instead."
            ),
        },
        "grounding_rule": (
            "Every answer must cite the record_id and dataset it came from. If no "
            "record supports an answer, reply 'insufficient evidence'. These files "
            "are complete, so absence here is real evidence of absence."
        ),
        "total_files": len(entries),
        "total_size_mb": round(sum(e["size_mb"] for e in entries), 2),
        "files": entries,
    }

    with (out_dir / "_manifest.json").open("w", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2, ensure_ascii=False)

    return manifest
