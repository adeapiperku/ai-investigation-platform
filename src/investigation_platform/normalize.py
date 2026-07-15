"""Normalize + deduplicate the raw KAPE/Velociraptor records into one
unified per-file schema, keyed by canonical path.

Every output record keeps a `provenance` list pointing back at the exact
(source_file, line_no) it was built from, so nothing downstream (graph,
anomaly detection, AI agent) can state a fact without a citation into
the original evidence JSON.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional

from .parsers import RawRecord, parse_case

# The two artifact result files we currently know how to fold in.
METADATA_RESULT = "Windows.KapeFiles.Targets%2FAll File Metadata.json"
UPLOADS_RESULT = "Windows.KapeFiles.Targets%2FUploads.json"


@dataclass
class Provenance:
    source_file: str
    line_no: int


@dataclass
class NormalizedFile:
    path: str
    size: Optional[int] = None
    uploaded_size: Optional[int] = None
    sha256: Optional[str] = None
    destination_file: Optional[str] = None
    created: Optional[str] = None
    changed: Optional[str] = None
    modified: Optional[str] = None
    last_accessed: Optional[str] = None
    seen_in_metadata: bool = False
    seen_in_uploads: bool = False
    seen_in_uploads_index: bool = False
    duplicate_lines: int = 0  # raw lines collapsed into this one record
    provenance: list[Provenance] = field(default_factory=list)

    def to_json(self) -> dict[str, Any]:
        d = asdict(self)
        return d


def canonical_path(raw_path: str) -> str:
    """Collapse incidental differences so the same file always keys the same.

    Velociraptor paths in these files are already in one consistent raw
    form (e.g. r"\\\\.\\C:\\$MFT"); we only need to fold case differences
    on the drive letter and strip trailing whitespace.
    """
    p = raw_path.strip()
    # Normalize drive-letter case: \\.\C:\... vs \\.\c:\...
    if len(p) >= 5 and p[4] == ":":
        p = p[:3] + p[3].upper() + p[4:]
    return p


def _merge_metadata(nf: NormalizedFile, rec: RawRecord) -> None:
    d = rec.data
    was_new = not nf.seen_in_metadata
    nf.seen_in_metadata = True
    if not was_new:
        nf.duplicate_lines += 1
    nf.size = nf.size if nf.size is not None else d.get("Size")
    nf.created = nf.created or d.get("Created")
    nf.changed = nf.changed or d.get("Changed")
    nf.modified = nf.modified or d.get("Modified")
    nf.last_accessed = nf.last_accessed or d.get("LastAccessed")
    nf.provenance.append(Provenance(rec.source_file, rec.line_no))


def _merge_uploads(nf: NormalizedFile, rec: RawRecord) -> None:
    d = rec.data
    was_new = not nf.seen_in_uploads
    nf.seen_in_uploads = True
    if not was_new:
        nf.duplicate_lines += 1
    nf.size = nf.size if nf.size is not None else d.get("FileSize")
    nf.sha256 = nf.sha256 or d.get("SourceFileSha256")
    nf.destination_file = nf.destination_file or d.get("DestinationFile")
    nf.created = nf.created or d.get("Created")
    nf.changed = nf.changed or d.get("Changed")
    nf.modified = nf.modified or d.get("Modified")
    nf.last_accessed = nf.last_accessed or d.get("LastAccessed")
    nf.provenance.append(Provenance(rec.source_file, rec.line_no))


def _merge_uploads_index(nf: NormalizedFile, rec: RawRecord) -> None:
    d = rec.data
    was_new = not nf.seen_in_uploads_index
    nf.seen_in_uploads_index = True
    if not was_new:
        nf.duplicate_lines += 1
    nf.uploaded_size = d.get("uploaded_size")
    nf.size = nf.size if nf.size is not None else d.get("file_size")
    nf.provenance.append(Provenance(rec.source_file, rec.line_no))


def normalize_case(case_root: Path) -> tuple[dict[str, NormalizedFile], dict[str, Any]]:
    """Parse a case and fold every file-oriented source into one record per path.

    Returns (records_by_path, stats) where stats reports raw line counts
    vs. unique paths, so dedup is auditable rather than silent.
    """
    case = parse_case(case_root)
    records: dict[str, NormalizedFile] = {}

    def get_or_create(path: str) -> NormalizedFile:
        key = canonical_path(path)
        if key not in records:
            records[key] = NormalizedFile(path=key)
        return records[key]

    raw_counts = {"metadata": 0, "uploads": 0, "uploads_index": 0}

    for rec in case["results"].get(METADATA_RESULT, []):
        src = rec.data.get("SourceFile")
        if not src:
            continue
        raw_counts["metadata"] += 1
        _merge_metadata(get_or_create(src), rec)

    for rec in case["results"].get(UPLOADS_RESULT, []):
        src = rec.data.get("SourceFile")
        if not src:
            continue
        raw_counts["uploads"] += 1
        _merge_uploads(get_or_create(src), rec)

    for rec in case["uploads_index"]:
        src = rec.data.get("vfs_path")
        if not src:
            continue
        raw_counts["uploads_index"] += 1
        _merge_uploads_index(get_or_create(src), rec)

    total_raw_lines = sum(raw_counts.values())
    stats = {
        "raw_line_counts": raw_counts,
        "total_raw_lines": total_raw_lines,
        "unique_paths": len(records),
        "duplicate_lines_collapsed": sum(nf.duplicate_lines for nf in records.values()),
    }
    return records, stats


def write_normalized(case_root: Path, out_dir: Path) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    records, stats = normalize_case(case_root)

    out_path = out_dir / "files.jsonl"
    with out_path.open("w", encoding="utf-8") as fh:
        for key in sorted(records):
            fh.write(json.dumps(records[key].to_json(), default=lambda o: asdict(o)) + "\n")

    stats_path = out_dir / "normalize_stats.json"
    with stats_path.open("w", encoding="utf-8") as fh:
        json.dump(stats, fh, indent=2)

    return stats


if __name__ == "__main__":
    import sys

    case_root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(
        "TriDsk-WKS02-C.1dfcd21bd3d01cc0-F.D3JVHAK4B16NM"
    )
    out_dir = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("data/normalized")
    stats = write_normalized(case_root, out_dir)
    print(json.dumps(stats, indent=2))
