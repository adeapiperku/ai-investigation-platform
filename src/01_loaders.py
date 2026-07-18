# python src/01_loaders.py
"""File discovery and structure-tolerant JSON/JSONL loading.

The loaders never raise on malformed input. Instead they return whatever
records could be parsed together with a list of *collection problems* that the
rest of the pipeline records without stopping.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Tuple

# File extensions treated as candidate datasets.
DATA_SUFFIXES = {".json", ".jsonl"}

# Keys that commonly wrap a list of records inside a single top-level object.
ARRAY_WRAPPER_KEYS = ("items", "rows", "results", "records", "data", "hits")


@dataclass
class CollectionProblem:
    """A single data-quality issue detected during loading or validation."""

    source_file: str
    problem_type: str
    detail: str
    record_id: str | None = None

    def as_dict(self) -> Dict[str, Any]:
        """Return a JSON-serializable representation of the problem."""
        return {
            "source_file": self.source_file,
            "problem_type": self.problem_type,
            "detail": self.detail,
            "record_id": self.record_id,
        }


@dataclass
class LoadedFile:
    """The outcome of loading one source file."""

    path: Path
    records: List[Dict[str, Any]] = field(default_factory=list)
    problems: List[CollectionProblem] = field(default_factory=list)


def discover_data_files(raw_dir: Path) -> List[Path]:
    """Recursively find all JSON/JSONL files under ``raw_dir``.

    Sidecar files such as ``*.json.index`` are ignored because they are binary
    offset indexes rather than JSON documents.
    """
    files: List[Path] = []
    for path in sorted(raw_dir.rglob("*")):
        if not path.is_file():
            continue
        if path.suffix.lower() not in DATA_SUFFIXES:
            continue
        if path.name.endswith(".json.index"):
            continue
        files.append(path)
    return files


def _relative_name(path: Path, root: Path) -> str:
    """Return a stable, human-readable identifier for a source file."""
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.name


def _coerce_to_records(payload: Any) -> List[Dict[str, Any]]:
    """Turn an arbitrary parsed JSON value into a list of record dicts."""
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        # A single object may wrap the real records under a known key.
        for key in ARRAY_WRAPPER_KEYS:
            value = payload.get(key)
            if isinstance(value, list) and all(isinstance(i, dict) for i in value):
                return value
        return [payload]
    return []


def _try_parse_whole(text: str) -> Tuple[bool, Any]:
    """Attempt to parse the entire file as a single JSON document."""
    try:
        return True, json.loads(text)
    except json.JSONDecodeError:
        return False, None


def _parse_jsonl(
    text: str, source_name: str
) -> Tuple[List[Dict[str, Any]], List[CollectionProblem]]:
    """Parse newline-delimited JSON, tolerating individual bad lines."""
    records: List[Dict[str, Any]] = []
    problems: List[CollectionProblem] = []
    for line_no, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError as exc:
            problems.append(
                CollectionProblem(
                    source_file=source_name,
                    problem_type="corrupted_json",
                    detail=f"line {line_no}: {exc.msg}",
                )
            )
            continue
        if isinstance(parsed, dict):
            records.append(parsed)
        elif isinstance(parsed, list):
            records.extend(i for i in parsed if isinstance(i, dict))
    return records, problems


def load_file(path: Path, root: Path) -> LoadedFile:
    """Load one file, auto-detecting object / array / JSONL structure.

    Detection strategy:
      1. Empty or zero-byte files are flagged and skipped.
      2. Try to parse the whole file as a single JSON document (covers objects,
         arrays and object-wrapped arrays, even when pretty-printed).
      3. Otherwise fall back to line-by-line JSONL parsing.
    """
    source_name = _relative_name(path, root)
    result = LoadedFile(path=path)

    try:
        raw_bytes = path.read_bytes()
    except OSError as exc:  # pragma: no cover - unlikely on local disk
        result.problems.append(
            CollectionProblem(source_name, "unreadable_file", str(exc))
        )
        return result

    if len(raw_bytes) == 0:
        result.problems.append(
            CollectionProblem(source_name, "zero_byte_file", "file is empty")
        )
        return result

    text = raw_bytes.decode("utf-8", errors="replace")
    if not text.strip():
        result.problems.append(
            CollectionProblem(source_name, "empty_file", "file has no content")
        )
        return result

    parsed_ok, payload = _try_parse_whole(text)
    if parsed_ok:
        result.records = _coerce_to_records(payload)
        if not result.records:
            result.problems.append(
                CollectionProblem(
                    source_name,
                    "no_records",
                    "parsed successfully but contained no object records",
                )
            )
        return result

    # Fall back to JSONL parsing.
    records, problems = _parse_jsonl(text, source_name)
    result.records = records
    result.problems.extend(problems)
    if not records and not problems:
        result.problems.append(
            CollectionProblem(source_name, "corrupted_json", "no parseable JSON found")
        )
    return result
