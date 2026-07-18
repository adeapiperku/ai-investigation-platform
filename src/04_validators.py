"""Record-level data-quality validation.

Validators inspect an already-normalized record and report collection
problems. They never raise; every issue is returned so the pipeline can keep
processing the remaining records.
"""

from __future__ import annotations

from typing import Any, Dict, List, Set

from .loaders import CollectionProblem

# Normalized fields that every record is expected to carry.
_REQUIRED_FIELDS = ("record_id", "source_file", "evidence_type", "original_data")


def validate_record(record: Dict[str, Any]) -> List[CollectionProblem]:
    """Check a single normalized record for missing timestamps/IDs/fields."""
    problems: List[CollectionProblem] = []
    source_file = record.get("source_file", "unknown")
    record_id = record.get("record_id")

    for field_name in _REQUIRED_FIELDS:
        if not record.get(field_name):
            problems.append(
                CollectionProblem(
                    source_file=source_file,
                    problem_type="missing_required_field",
                    detail=f"missing '{field_name}'",
                    record_id=record_id,
                )
            )

    if not record.get("timestamp"):
        problems.append(
            CollectionProblem(
                source_file=source_file,
                problem_type="missing_timestamp",
                detail="no interpretable timestamp found",
                record_id=record_id,
            )
        )

    if not record.get("identifiers"):
        problems.append(
            CollectionProblem(
                source_file=source_file,
                problem_type="missing_identifiers",
                detail="no correlation identifiers extracted",
                record_id=record_id,
            )
        )

    return problems


def detect_duplicates(records: List[Dict[str, Any]]) -> List[CollectionProblem]:
    """Flag records whose original payload is an exact duplicate.

    Duplicates are detected per source file using a hash of the original data
    so that identical rows from different files are not falsely merged.
    """
    problems: List[CollectionProblem] = []
    seen: Set[tuple] = set()
    for record in records:
        signature = (
            record.get("source_file"),
            _fingerprint(record.get("original_data")),
        )
        if signature in seen:
            problems.append(
                CollectionProblem(
                    source_file=record.get("source_file", "unknown"),
                    problem_type="duplicate_record",
                    detail="identical original payload already seen in this file",
                    record_id=record.get("record_id"),
                )
            )
        else:
            seen.add(signature)
    return problems


def _fingerprint(data: Any) -> int:
    """Return a stable hash for arbitrary JSON-compatible data."""
    import json

    try:
        return hash(json.dumps(data, sort_keys=True, default=str))
    except (TypeError, ValueError):
        return hash(str(data))
