"""Orchestration: build the normalized investigation dataset.

Ties together loading, normalization, extraction and validation to produce the
final ``normalized_dataset.json`` structure:

    {
      "dataset_metadata": {...},
      "summary": {...},
      "collection_problems": [...],
      "normalized_records": [...]
    }
"""

from __future__ import annotations

import hashlib
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from .extractors import classify_evidence, extract_identifiers, extract_timestamp
from .loaders import (
    CollectionProblem,
    LoadedFile,
    discover_data_files,
    load_file,
)
from .normalizers import normalize_path
from .validators import detect_duplicates, validate_record


def _make_record_id(source_name: str, index: int, record: Dict[str, Any]) -> str:
    """Create a deterministic record id from source, position and content."""
    digest = hashlib.sha1(
        f"{source_name}:{index}:{sorted(record.items(), key=lambda kv: kv[0])}".encode(
            "utf-8", errors="replace"
        )
    ).hexdigest()[:12]
    return f"{Path(source_name).name}:{index}:{digest}"


def _best_path(record: Dict[str, Any], identifiers: Dict[str, str]) -> Dict[str, Any]:
    """Normalize the primary file path referenced by a record, if any."""
    raw_path = identifiers.get("file_path")
    if raw_path:
        return normalize_path(raw_path)
    return normalize_path(None)


def _build_record(
    raw: Dict[str, Any], source_name: str, index: int
) -> Dict[str, Any]:
    """Assemble one normalized record while preserving the original data."""
    identifiers = extract_identifiers(raw)
    timestamp = extract_timestamp(raw)
    path_fields = _best_path(raw, identifiers)
    evidence_type = classify_evidence(raw, source_name)

    return {
        "record_id": _make_record_id(source_name, index, raw),
        "source_file": source_name,
        "evidence_type": evidence_type,
        "timestamp": timestamp,
        "identifiers": identifiers,
        "path": path_fields,
        "original_data": raw,
    }


def _summarize(
    records: List[Dict[str, Any]],
    source_files: List[str],
    problems: List[CollectionProblem],
) -> Dict[str, Any]:
    """Compute dataset-level summary statistics."""

    def collect(field: str) -> List[str]:
        values = {
            r["identifiers"][field]
            for r in records
            if r["identifiers"].get(field)
        }
        return sorted(values)

    urls = collect("url")
    problem_counts = Counter(p.problem_type for p in problems)
    evidence_counts = Counter(r["evidence_type"] for r in records)

    return {
        "num_source_files": len(source_files),
        "num_records": len(records),
        "identified_users": collect("username"),
        "identified_hosts": collect("hostname"),
        "identified_applications": collect("application"),
        "identified_repositories": collect("repository"),
        "identified_urls": urls,
        "identified_cves": collect("cve"),
        "identified_ips": collect("ip"),
        "identified_hashes_count": len(collect("hash")),
        "evidence_type_counts": dict(sorted(evidence_counts.items())),
        "collection_issue_counts": dict(sorted(problem_counts.items())),
        "total_collection_issues": len(problems),
    }


def build_dataset(raw_dir: Path) -> Dict[str, Any]:
    """Run the full normalization pipeline over ``raw_dir``.

    Returns the complete dataset dictionary ready to be serialized to JSON.
    """
    files = discover_data_files(raw_dir)
    all_records: List[Dict[str, Any]] = []
    all_problems: List[CollectionProblem] = []
    source_names: List[str] = []

    for path in files:
        loaded: LoadedFile = load_file(path, raw_dir)
        source_name = _relative(path, raw_dir)
        source_names.append(source_name)
        all_problems.extend(loaded.problems)

        for index, raw in enumerate(loaded.records):
            record = _build_record(raw, source_name, index)
            all_records.append(record)
            all_problems.extend(validate_record(record))

    all_problems.extend(detect_duplicates(all_records))

    summary = _summarize(all_records, source_names, all_problems)
    metadata = {
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "phase": "Phase 1 - Data Normalization",
        "raw_data_dir": str(raw_dir),
        "source_files": source_names,
        "record_schema": [
            "record_id",
            "source_file",
            "evidence_type",
            "timestamp",
            "identifiers",
            "path",
            "original_data",
        ],
    }

    return {
        "dataset_metadata": metadata,
        "summary": summary,
        "collection_problems": [p.as_dict() for p in all_problems],
        "normalized_records": all_records,
    }


def _relative(path: Path, root: Path) -> str:
    """Return a POSIX-style path relative to the raw data root."""
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.name
