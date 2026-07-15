"""Detect collection problems and anomalies from the normalized dataset
and the raw collection metadata/log.

Every finding here references concrete data (a path + its provenance, or
a specific log line / count) - nothing is inferred without a pointer
back to the evidence that supports it.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def _load_normalized(normalized_dir: Path) -> list[dict[str, Any]]:
    path = normalized_dir / "files.jsonl"
    with path.open("r", encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def _load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def find_size_mismatches(files: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Files where the size on disk doesn't match what actually got uploaded.

    This indicates a truncated / partial collection for that specific file
    (e.g. locked file, read error, size changed mid-collection).
    """
    out = []
    for f in files:
        size = f.get("size")
        uploaded = f.get("uploaded_size")
        if size is not None and uploaded is not None and size != uploaded:
            out.append(
                {
                    "path": f["path"],
                    "expected_size": size,
                    "uploaded_size": uploaded,
                    "shortfall": size - uploaded,
                    "provenance": f["provenance"],
                }
            )
    return out


def find_metadata_without_upload(files: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Files whose metadata was recorded (they were seen/targeted) but no
    upload record and no upload-index entry exists for them -- i.e. the
    collector saw the file but it never actually made it into evidence."""
    out = []
    for f in files:
        if f["seen_in_metadata"] and not f["seen_in_uploads"] and not f["seen_in_uploads_index"]:
            out.append({"path": f["path"], "size": f.get("size"), "provenance": f["provenance"]})
    return out


def find_uploaded_without_metadata(files: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Files that were uploaded/indexed but have no matching 'All File
    Metadata' record -- unexpected, worth a second look."""
    out = []
    for f in files:
        if (f["seen_in_uploads"] or f["seen_in_uploads_index"]) and not f["seen_in_metadata"]:
            out.append({"path": f["path"], "provenance": f["provenance"]})
    return out


def check_collection_totals(case_root: Path) -> dict[str, Any]:
    """Compare the collection job's own expected vs. actual byte/file counts."""
    ctx = _load_json(case_root / "collection_context.json")
    expected_bytes = ctx.get("total_expected_uploaded_bytes")
    actual_bytes = ctx.get("total_uploaded_bytes")
    total_files = ctx.get("total_uploaded_files")
    shortfall = None
    pct_complete = None
    if expected_bytes and actual_bytes is not None:
        shortfall = expected_bytes - actual_bytes
        pct_complete = round(100 * actual_bytes / expected_bytes, 2)
    return {
        "total_uploaded_files": total_files,
        "expected_bytes": expected_bytes,
        "actual_bytes": actual_bytes,
        "shortfall_bytes": shortfall,
        "pct_complete": pct_complete,
        "source": "collection_context.json",
    }


def scan_log_for_problems(case_root: Path) -> list[dict[str, Any]]:
    """Pull out any log lines that indicate errors/warnings during collection."""
    log_path = case_root / "log.json"
    if not log_path.exists():
        return []
    problems = []
    for line_no, rec in enumerate(_load_jsonl(log_path), start=1):
        level = rec.get("level", "")
        if level not in ("DEFAULT", "INFO"):
            problems.append({"line_no": line_no, "level": level, "message": rec.get("message")})
    return problems


def run_all(case_root: Path, normalized_dir: Path) -> dict[str, Any]:
    files = _load_normalized(normalized_dir)
    report = {
        "collection_totals": check_collection_totals(case_root),
        "log_problems": scan_log_for_problems(case_root),
        "size_mismatches": find_size_mismatches(files),
        "metadata_without_upload": find_metadata_without_upload(files),
        "uploaded_without_metadata": find_uploaded_without_metadata(files),
    }
    report["summary"] = {
        "size_mismatch_count": len(report["size_mismatches"]),
        "metadata_without_upload_count": len(report["metadata_without_upload"]),
        "uploaded_without_metadata_count": len(report["uploaded_without_metadata"]),
        "log_problem_count": len(report["log_problems"]),
    }
    return report


def write_report(case_root: Path, normalized_dir: Path, out_dir: Path) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    report = run_all(case_root, normalized_dir)
    out_path = out_dir / "anomalies.json"
    with out_path.open("w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
    return report


if __name__ == "__main__":
    import sys

    case_root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(
        "TriDsk-WKS02-C.1dfcd21bd3d01cc0-F.D3JVHAK4B16NM"
    )
    normalized_dir = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("data/normalized")
    out_dir = Path(sys.argv[3]) if len(sys.argv) > 3 else Path("data/reports")
    report = write_report(case_root, normalized_dir, out_dir)
    print(json.dumps(report["summary"], indent=2))
    print(json.dumps(report["collection_totals"], indent=2))
