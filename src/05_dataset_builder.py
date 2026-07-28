"""Per-dataset normalization.

Each dataset in :mod:`src.dataset_registry` is normalized **on its own**, into
its own output file, using one shared record schema:

    {
      "record_id":     "<dataset>:<index>:<digest>",
      "dataset":       "browser_downloads",
      "source_file":   "uploads/auto/.../History",
      "evidence_type": "browser_download",
      "timestamp":     "2025-10-09T18:02:20Z",   # UTC ISO-8601, or null
      "identifiers":   {...},                    # correlation keys
      "path":          {...},                    # decomposed file path
      "original_data": {...}                     # the dataset's own payload
    }

Every dataset produces records in exactly that shape, which is what makes them
comparable without being merged. A source file that fails to parse costs you
that one dataset, not the whole run.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

from .dataset_registry import DATASETS, DatasetSpec
from .extractors import extract_identifiers, extract_timestamp
from .loaders import CollectionProblem
from .normalizers import normalize_path, normalize_timestamp
from .validators import validate_record

# The record schema every dataset conforms to.
RECORD_SCHEMA: Tuple[str, ...] = (
    "record_id",
    "dataset",
    "provenance",
    "source_file",
    "evidence_type",
    "timestamp",
    "identifiers",
    "path",
    "original_data",
)

# Identifiers that only mean something when they describe the endpoint. A CVE or
# URL quoted in the collector's own configuration is documentation, not an
# indicator, so these are not extracted from ``collection_tooling`` datasets.
_ENDPOINT_ONLY_IDENTIFIERS: Tuple[str, ...] = ("cve", "url", "ip", "hash", "domain")

# Timestamp fields the generic extractor does not know about, per dataset.
_EXTRA_TIMESTAMP_KEYS: Dict[str, Tuple[str, ...]] = {
    "browser_history": ("last_visit_utc",),
    "browser_downloads": ("start_time_utc", "end_time_utc"),
    "onedrive_sync": ("log_timestamp",),
    "shell_links": ("target_modified", "target_created"),
    "registry_user": ("key_last_written", "hive_last_written"),
}

# Payload keys that hold a file path, in priority order, beyond what the generic
# extractor already checks.
_EXTRA_PATH_KEYS: Tuple[str, ...] = (
    "target_path",
    "local_base_path",
    "_artifact_source",
)


def _make_record_id(dataset: str, index: int, payload: Dict[str, Any]) -> str:
    """Create a deterministic record id from dataset, position and content."""
    try:
        body = json.dumps(payload, sort_keys=True, default=str)
    except (TypeError, ValueError):
        body = repr(payload)
    digest = hashlib.sha1(f"{dataset}:{index}:{body}".encode("utf-8", "replace")).hexdigest()
    return f"{dataset}:{index}:{digest[:12]}"


def _resolve_timestamp(payload: Dict[str, Any], spec: DatasetSpec) -> str | None:
    """Find this record's most relevant timestamp, normalized to UTC ISO-8601."""
    for key in _EXTRA_TIMESTAMP_KEYS.get(spec.name, ()):
        value = payload.get(key)
        if value:
            normalized = normalize_timestamp(value)
            if normalized:
                return normalized
    return extract_timestamp(payload)


def _resolve_path(payload: Dict[str, Any], identifiers: Dict[str, str]) -> Dict[str, Any]:
    """Decompose the primary file path this record refers to."""
    raw = identifiers.get("file_path")
    if not raw:
        for key in _EXTRA_PATH_KEYS:
            value = payload.get(key)
            if isinstance(value, str) and value.strip():
                raw = value
                break
    return normalize_path(raw)


def normalize_record(
    payload: Dict[str, Any], spec: DatasetSpec, index: int
) -> Dict[str, Any]:
    """Turn one raw payload into a record in the shared schema."""
    source_file = payload.get("_artifact_source") or spec.name
    body = {
        key: value
        for key, value in payload.items()
        if key != "_artifact_source" and key not in spec.drop_fields
    }

    identifiers = extract_identifiers(body)
    if spec.provenance != "endpoint_evidence":
        # See _ENDPOINT_ONLY_IDENTIFIERS: the collector's own configuration
        # quotes CVEs and URLs that have nothing to do with this endpoint.
        for key in _ENDPOINT_ONLY_IDENTIFIERS:
            identifiers.pop(key, None)

    path_fields = _resolve_path({**body, "_artifact_source": source_file}, identifiers)

    # A profile-scoped artifact attributes to its profile owner even when the
    # payload itself never names a user.
    if "username" not in identifiers and path_fields.get("username"):
        identifiers["username"] = path_fields["username"]

    return {
        "record_id": _make_record_id(spec.name, index, body),
        "dataset": spec.name,
        "provenance": spec.provenance,
        "source_file": source_file,
        "evidence_type": spec.evidence_type,
        "timestamp": _resolve_timestamp(payload, spec),
        "identifiers": identifiers,
        "path": path_fields,
        "original_data": body,
    }


def _summarize(
    records: List[Dict[str, Any]], problems: List[CollectionProblem]
) -> Dict[str, Any]:
    """Compute dataset-level summary statistics."""

    def collect(field_name: str) -> List[str]:
        return sorted(
            {
                record["identifiers"][field_name]
                for record in records
                if record["identifiers"].get(field_name)
            }
        )

    timestamps = sorted(r["timestamp"] for r in records if r["timestamp"])
    return {
        "num_records": len(records),
        "records_with_timestamp": len(timestamps),
        "time_range": (
            {"first": timestamps[0], "last": timestamps[-1]} if timestamps else None
        ),
        "identified_users": collect("username"),
        "identified_hosts": collect("hostname"),
        "identified_urls": collect("url"),
        "identified_ips": collect("ip"),
        "identified_cves": collect("cve"),
        "identified_hashes_count": len(collect("hash")),
        "collection_issue_counts": dict(
            sorted(Counter(p.problem_type for p in problems).items())
        ),
        "total_collection_issues": len(problems),
    }


def build_one(spec: DatasetSpec, raw_dir: Path) -> Dict[str, Any]:
    """Normalize a single dataset into its self-contained output document."""
    files = spec.discover(raw_dir)
    if files:
        payloads, problems = spec.read(files, raw_dir)
    else:
        payloads, problems = [], [
            CollectionProblem(spec.name, "dataset_not_collected", "no source files found")
        ]

    records: List[Dict[str, Any]] = []
    for index, payload in enumerate(payloads):
        if not isinstance(payload, dict):
            continue
        record = normalize_record(payload, spec, index)
        records.append(record)
        problems.extend(validate_record(record))

    if files and not records:
        problems.append(
            CollectionProblem(
                spec.name, "no_records", "source files held no usable records"
            )
        )

    source_files = sorted({_relative(path, raw_dir) for path in files})
    return {
        "dataset": {
            "name": spec.name,
            "provenance": spec.provenance,
            "evidence_type": spec.evidence_type,
            "description": spec.description,
            "answers_questions": list(spec.answers_questions),
            "source_files": source_files[:100],
            "num_source_files": len(source_files),
            "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "record_schema": list(RECORD_SCHEMA),
        },
        "summary": _summarize(records, problems),
        "collection_problems": [problem.as_dict() for problem in problems],
        "records": records,
    }


def build_all(raw_dir: Path) -> List[Tuple[DatasetSpec, Dict[str, Any]]]:
    """Normalize every registered dataset, independently, in catalogue order."""
    return [(spec, build_one(spec, raw_dir)) for spec in DATASETS]


def _relative(path: Path, root: Path) -> str:
    """Return a POSIX-style path relative to the raw data root."""
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.name
