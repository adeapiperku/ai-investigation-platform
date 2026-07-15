"""Parsers for the raw JSON/JSONL files produced by a Velociraptor KAPE
triage collection (client_info, collection_context, log, requests,
uploads index, and per-artifact results).

Every parser is a thin, honest reader: it does not invent or drop fields,
it just yields dicts so downstream normalization has a stable starting
point and can always point back at "this came from line N of file X".
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator


@dataclass(frozen=True)
class RawRecord:
    """A single parsed JSON record plus provenance for citation."""

    source_file: str  # relative path of the JSON file this came from
    line_no: int  # 1-indexed line number (or 0 for single-object files)
    data: dict[str, Any]


def _iter_jsonl(path: Path) -> Iterator[tuple[int, dict[str, Any]]]:
    with path.open("r", encoding="utf-8") as fh:
        for line_no, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            yield line_no, json.loads(line)


def parse_jsonl_file(case_root: Path, relative_path: str) -> list[RawRecord]:
    """Parse a JSON-Lines file (one JSON object per line)."""
    path = case_root / relative_path
    return [
        RawRecord(source_file=relative_path, line_no=line_no, data=obj)
        for line_no, obj in _iter_jsonl(path)
    ]


def parse_single_json_object(case_root: Path, relative_path: str) -> RawRecord:
    """Parse a file containing exactly one JSON object (e.g. client_info.json)."""
    path = case_root / relative_path
    with path.open("r", encoding="utf-8") as fh:
        obj = json.load(fh)
    return RawRecord(source_file=relative_path, line_no=0, data=obj)


def parse_case(case_root: Path) -> dict[str, Any]:
    """Parse every known JSON artifact in a case root directory.

    Returns a dict keyed by logical name -> parsed records. Files that
    don't exist are silently skipped (a case may not have run every
    artifact type) but this is reported by normalize.py, not hidden.
    """
    case_root = Path(case_root)
    result: dict[str, Any] = {}

    single_object_files = {
        "client_info": "client_info.json",
        "collection_context": "collection_context.json",
        "requests": "requests.json",
    }
    for name, rel in single_object_files.items():
        p = case_root / rel
        if p.exists():
            result[name] = parse_single_json_object(case_root, rel)
        else:
            result[name] = None

    jsonl_files = {
        "log": "log.json",
        "uploads_index": "uploads.json",
    }
    for name, rel in jsonl_files.items():
        p = case_root / rel
        result[name] = parse_jsonl_file(case_root, rel) if p.exists() else []

    # results/ directory holds one JSONL file per artifact source, with
    # '%2F' standing in for '/' in the artifact name (URL-encoded by
    # Velociraptor when it wrote the filename).
    results_dir = case_root / "results"
    result["results"] = {}
    if results_dir.exists():
        for f in sorted(results_dir.glob("*.json")):
            rel = f"results/{f.name}"
            result["results"][f.name] = parse_jsonl_file(case_root, rel)

    return result
