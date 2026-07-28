# python 01_normalize_datasets.py
"""Phase 1: normalize each dataset in the collection, independently.

Usage:
    python 01_normalize_datasets.py [--raw DIR] [--out DIR] [--only NAME ...]

Every dataset in the catalogue (``src/11_dataset_registry.py``) is read,
normalized into the shared record schema, and written to its **own** file:

    data/normalized/client_info.normalized.json
    data/normalized/browser_downloads.normalized.json
    data/normalized/onedrive_sync.normalized.json
    ...

plus ``data/normalized/_manifest.json`` describing the whole set. Datasets do
not get merged: one bad source file costs you one dataset, and re-running a
single dataset with ``--only`` costs seconds instead of minutes.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from src.dataset_builder import RECORD_SCHEMA, build_one
from src.dataset_registry import DATASETS, DATASETS_BY_NAME
from src.derived_datasets import build_collection_gap, build_program_execution

DEFAULT_RAW = Path("data/raw")
DEFAULT_OUT = Path("data/normalized")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Phase 1: per-dataset normalization",
        epilog="datasets: " + ", ".join(spec.name for spec in DATASETS),
    )
    parser.add_argument("--raw", type=Path, default=DEFAULT_RAW, help="raw data directory")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT, help="output directory")
    parser.add_argument(
        "--only",
        nargs="+",
        metavar="NAME",
        help="normalize only these datasets (default: all)",
    )
    parser.add_argument(
        "--list", action="store_true", help="list the dataset catalogue and exit"
    )
    return parser.parse_args(argv)


def _write(document: dict, path: Path) -> float:
    """Write one dataset document compactly and return its size in MB."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(document, handle, ensure_ascii=False, default=str)
    return path.stat().st_size / (1024 * 1024)


def main(argv: list[str] | None = None) -> int:
    """Normalize each dataset and write one output file per dataset."""
    args = parse_args(argv)

    if args.list:
        for spec in DATASETS:
            questions = ", ".join(f"Q{n}" for n in spec.answers_questions) or "-"
            print(f"{spec.name:<22} {spec.evidence_type:<18} {questions}")
        return 0

    if not args.raw.exists():
        print(f"error: raw data directory not found: {args.raw}", file=sys.stderr)
        return 1

    if args.only:
        unknown = [name for name in args.only if name not in DATASETS_BY_NAME]
        if unknown:
            print(
                f"error: unknown dataset(s): {', '.join(unknown)}\n"
                f"known: {', '.join(DATASETS_BY_NAME)}",
                file=sys.stderr,
            )
            return 1
        specs = [DATASETS_BY_NAME[name] for name in args.only]
    else:
        specs = list(DATASETS)

    print(f"Normalizing {len(specs)} dataset(s) from {args.raw} ...\n")
    print(f"{'dataset':<22}{'records':>9}{'sources':>9}{'issues':>8}{'MB':>8}")
    print("-" * 56)

    entries = []
    for spec in specs:
        document = build_one(spec, args.raw)
        target = args.out / f"{spec.name}.normalized.json"
        size_mb = _write(document, target)

        summary = document["summary"]
        meta = document["dataset"]
        print(
            f"{spec.name:<22}{summary['num_records']:>9}"
            f"{meta['num_source_files']:>9}"
            f"{summary['total_collection_issues']:>8}{size_mb:>8.1f}"
        )
        entries.append(
            {
                "name": spec.name,
                "file": target.name,
                "evidence_type": spec.evidence_type,
                "description": spec.description,
                "answers_questions": list(spec.answers_questions),
                "num_records": summary["num_records"],
                "num_source_files": meta["num_source_files"],
                "time_range": summary["time_range"],
                "collection_issues": summary["total_collection_issues"],
                "size_mb": round(size_mb, 2),
            }
        )

    # Derived datasets are built from other datasets rather than a raw source,
    # so they run after the catalogue and only when their inputs were produced.
    built = {entry["name"] for entry in entries}
    for name, inputs, build in (
        ("program_execution", ("file_metadata",), lambda docs: build_program_execution(docs[0])),
        (
            "collection_gap",
            ("upload_manifest",),
            lambda docs: build_collection_gap(docs[0], args.raw / "uploads" / "auto"),
        ),
    ):
        if not all(source in built for source in inputs):
            continue
        try:
            docs = [
                json.loads((args.out / f"{source}.normalized.json").read_text(encoding="utf-8"))
                for source in inputs
            ]
        except (OSError, ValueError) as exc:
            print(f"warning: cannot build {name}: {exc}", file=sys.stderr)
            continue

        document = build(docs)
        target = args.out / f"{name}.normalized.json"
        size_mb = _write(document, target)
        summary = document["summary"]
        print(
            f"{name:<22}{summary['num_records']:>9}{'derived':>9}{0:>8}{size_mb:>8.1f}"
        )
        entries.append(
            {
                "name": name,
                "file": target.name,
                "evidence_type": document["dataset"]["evidence_type"],
                "description": document["dataset"]["description"],
                "answers_questions": document["dataset"]["answers_questions"],
                "num_records": summary["num_records"],
                "num_source_files": 0,
                "time_range": summary["time_range"],
                "collection_issues": 0,
                "size_mb": round(size_mb, 2),
                "derived": True,
            }
        )

    # Merge into any existing manifest so a --only run does not lose the rest.
    manifest_path = args.out / "_manifest.json"
    existing: list[dict] = []
    if manifest_path.is_file():
        try:
            with manifest_path.open(encoding="utf-8") as handle:
                existing = json.load(handle).get("datasets", [])
        except (OSError, ValueError):
            existing = []

    by_name = {entry["name"]: entry for entry in existing}
    by_name.update({entry["name"]: entry for entry in entries})
    # Catalogue order first, then any derived datasets (which are not in it).
    ordered = [by_name[spec.name] for spec in DATASETS if spec.name in by_name]
    catalogued = {spec.name for spec in DATASETS}
    ordered += [entry for name, entry in by_name.items() if name not in catalogued]

    manifest = {
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "raw_data_dir": str(args.raw),
        "record_schema": list(RECORD_SCHEMA),
        "num_datasets": len(ordered),
        "total_records": sum(entry["num_records"] for entry in ordered),
        "datasets": ordered,
    }
    with manifest_path.open("w", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2, ensure_ascii=False)

    print("-" * 56)
    print(f"{'total':<22}{manifest['total_records']:>9}")
    print(f"\nWrote {len(entries)} dataset file(s) + manifest to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
