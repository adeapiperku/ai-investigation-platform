"""Datasets derived from other datasets, not from a new raw source.

Two facts about this collection are true but invisible, because each is spread
across tens of thousands of rows of a bulk dataset:

*Prefetch.* Windows writes ``C:\\Windows\\Prefetch\\NAME.EXE-HASH.pf`` when a
program runs, and rewrites it on each subsequent run. The ``.pf`` files
themselves were not preserved here, but their **metadata rows were** — and a
prefetch file's own modified time is, to the second, the last time that program
executed. With no Security or Sysmon logs in this collection, that is the only
execution timeline available. It should not be buried among 26 000 file rows.

*The collection gap.* The upload manifest lists every file Velociraptor
collected on the endpoint. The extract on disk holds far fewer. Every file in
the difference was collected and then lost in transit — which is a completely
different finding from "the file never existed". Without this dataset an
analyst cannot tell the two apart, and will report absence of evidence as
evidence of absence.
"""

from __future__ import annotations

import hashlib
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

# C:\Windows\Prefetch\CHROME.EXE-A1B2C3D4.pf
_PREFETCH_RE = re.compile(r"^(?P<program>.+?)-(?P<hash>[0-9A-F]{7,8})\.pf$", re.IGNORECASE)

_BACKSLASH = chr(92)


def _record_id(dataset: str, index: int, seed: str) -> str:
    """Create a deterministic record id matching the shared schema."""
    digest = hashlib.sha1(f"{dataset}:{index}:{seed}".encode("utf-8", "replace")).hexdigest()
    return f"{dataset}:{index}:{digest[:12]}"


def _envelope(dataset: str, evidence_type: str, description: str,
              records: List[Dict[str, Any]], questions: List[int]) -> Dict[str, Any]:
    """Wrap derived records in the same document shape as a normalized dataset."""
    timestamps = sorted(r["timestamp"] for r in records if r.get("timestamp"))
    return {
        "dataset": {
            "name": dataset,
            "provenance": "endpoint_evidence",
            "evidence_type": evidence_type,
            "description": description,
            "answers_questions": questions,
            "source_files": ["(derived)"],
            "num_source_files": 0,
            "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "derived": True,
        },
        "summary": {
            "num_records": len(records),
            "records_with_timestamp": len(timestamps),
            "time_range": (
                {"first": timestamps[0], "last": timestamps[-1]} if timestamps else None
            ),
        },
        "collection_problems": [],
        "records": records,
    }


# --------------------------------------------------------------------------- #
# Program execution, from prefetch file metadata
# --------------------------------------------------------------------------- #


def build_program_execution(file_metadata: Dict[str, Any]) -> Dict[str, Any]:
    """Extract a program-execution timeline from prefetch file metadata.

    The ``.pf`` file's own last-modified time is when the program last ran. Its
    creation time is when the program was *first* seen running on this host.
    """
    records: List[Dict[str, Any]] = []

    for source in file_metadata.get("records", []):
        path = (source.get("path") or {}).get("full_path") or ""
        filename = (source.get("path") or {}).get("filename") or ""
        if "prefetch" not in path.lower() or not filename.lower().endswith(".pf"):
            continue

        match = _PREFETCH_RE.match(filename)
        if not match:
            continue

        payload = source.get("original_data") or {}
        program = match.group("program").upper()
        # Modified is aliased to Changed upstream; fall back across both.
        last_run = payload.get("Modified") or payload.get("Changed") or source.get("timestamp")
        first_run = payload.get("Created")

        index = len(records)
        records.append(
            {
                "record_id": _record_id("program_execution", index, filename),
                "dataset": "program_execution",
                "provenance": "endpoint_evidence",
                "source_file": source.get("source_file"),
                "evidence_type": "program_execution",
                "timestamp": last_run,
                "identifiers": {"process": program},
                "path": {"full_path": path, "filename": filename},
                "original_data": {
                    "program": program,
                    "last_run": last_run,
                    "first_run": first_run,
                    "prefetch_file": filename,
                    "prefetch_hash": match.group("hash").upper(),
                    "derived_from_record_id": source.get("record_id"),
                    "note": (
                        "Last-run time is the prefetch file's own modified timestamp. "
                        "The .pf file itself was not preserved, so the run count and "
                        "the loaded-file list it contains are not available."
                    ),
                },
            }
        )

    records.sort(key=lambda r: (r.get("timestamp") or ""))
    return _envelope(
        "program_execution",
        "program_execution",
        "Program execution timeline recovered from Windows Prefetch file metadata: "
        "which executables ran on this host, when each last ran and when each was "
        "first seen. The only execution evidence in this collection - no Security "
        "event log, Sysmon or Amcache was preserved.",
        records,
        [1, 2, 12, 13],
    )


# --------------------------------------------------------------------------- #
# The collection gap
# --------------------------------------------------------------------------- #


def build_collection_gap(
    upload_manifest: Dict[str, Any], uploads_root: Path
) -> Dict[str, Any]:
    """List files Velociraptor collected that are absent from this extract.

    A file here was present on the endpoint and was successfully collected — it
    simply did not survive into the copy being analyzed. Any question that turns
    on such a file is unanswerable from this data, but the correct finding is
    "collected, not delivered", never "did not exist".
    """
    records: List[Dict[str, Any]] = []

    for source in upload_manifest.get("records", []):
        path = (source.get("path") or {}).get("full_path") or ""
        # Raw-device paths (\\.\C:\$MFT) never extract to a normal file tree.
        if not path or path.startswith(_BACKSLASH * 2):
            continue

        relative = path.replace("C:", "C%3A").replace(_BACKSLASH, "/")
        if os.path.exists(uploads_root / relative):
            continue

        payload = source.get("original_data") or {}
        index = len(records)
        records.append(
            {
                "record_id": _record_id("collection_gap", index, path),
                "dataset": "collection_gap",
                "provenance": "endpoint_evidence",
                "source_file": source.get("source_file"),
                "evidence_type": "missing_artifact",
                "timestamp": source.get("timestamp"),
                "identifiers": {
                    k: v for k, v in {
                        "file_path": path,
                        "username": (source.get("identifiers") or {}).get("username"),
                        "hash": payload.get("SourceFileSha256"),
                    }.items() if v
                },
                "path": source.get("path") or {},
                "original_data": {
                    "collected_path": path,
                    "file_size": payload.get("FileSize"),
                    "sha256": payload.get("SourceFileSha256"),
                    "collected_at": source.get("timestamp"),
                    "status": "collected_but_absent_from_this_extract",
                    "derived_from_record_id": source.get("record_id"),
                },
            }
        )

    return _envelope(
        "collection_gap",
        "missing_artifact",
        "Files that Velociraptor successfully collected from the endpoint but "
        "which are NOT present in this extract. Their content cannot be examined. "
        "A question depending on one of these is unanswerable from this data - but "
        "the file did exist on the host, so this is 'collected, not delivered', "
        "never 'never existed'.",
        records,
        [4, 5, 7, 8, 12, 13],
    )
