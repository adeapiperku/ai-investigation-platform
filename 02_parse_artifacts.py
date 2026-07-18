# python 02_parse_artifacts.py
"""Phase 1b entry point: parse binary artifacts into the dataset.

Usage:
    python 02_parse_artifacts.py [--raw DIR] [--dataset FILE]

Parses the Chromium/Edge ``History`` SQLite databases collected under
``data/raw/uploads/auto/...`` and appends the resulting browsing / download
records (same normalized schema) to ``normalized_dataset.json`` in place, so the
knowledge graph, cleaning and agent stages can use browser evidence.

Run after Phase 1 (``01_build_dataset.py``). Re-running is safe: previously
parsed artifact records are replaced, not duplicated.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from src.artifact_parser import ARTIFACT_EVIDENCE_TYPES, parse_artifacts

DEFAULT_RAW = Path("data/raw")
DEFAULT_DATASET = Path("data/processed/normalized_dataset.json")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="Phase 1b binary-artifact parser")
    parser.add_argument("--raw", type=Path, default=DEFAULT_RAW)
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    return parser.parse_args(argv)


def _refresh_url_summary(dataset: dict) -> None:
    """Recompute the dataset's URL list from all record identifiers."""
    urls = sorted(
        {
            r["identifiers"]["url"]
            for r in dataset.get("normalized_records", [])
            if r.get("identifiers", {}).get("url")
        }
    )
    dataset.setdefault("summary", {})["identified_urls"] = urls


def main(argv: list[str] | None = None) -> int:
    """Parse artifacts and merge their records into the dataset."""
    args = parse_args(argv)

    if not args.dataset.exists():
        print(
            f"error: normalized dataset not found: {args.dataset}\n"
            "run Phase 1 first:  python 01_build_dataset.py",
            file=sys.stderr,
        )
        return 1
    if not args.raw.exists():
        print(f"error: raw data directory not found: {args.raw}", file=sys.stderr)
        return 1

    print(f"Loading {args.dataset} ...")
    with args.dataset.open(encoding="utf-8") as handle:
        dataset = json.load(handle)

    print(f"Parsing binary artifacts under {args.raw} ...")
    result = parse_artifacts(args.raw)

    # Idempotent merge: drop any previously parsed artifact records first.
    records = [
        r
        for r in dataset.get("normalized_records", [])
        if r.get("evidence_type") not in ARTIFACT_EVIDENCE_TYPES
    ]
    records.extend(result["records"])
    dataset["normalized_records"] = records

    # Fold the artifact collection problems into the dataset.
    problems = dataset.get("collection_problems", [])
    problems.extend(p.as_dict() for p in result["problems"])
    dataset["collection_problems"] = problems

    dataset.setdefault("summary", {})["num_records"] = len(records)
    _refresh_url_summary(dataset)
    dataset.setdefault("dataset_metadata", {})["artifact_stats"] = result["stats"]

    with args.dataset.open("w", encoding="utf-8") as handle:
        json.dump(dataset, handle, indent=2, ensure_ascii=False, default=str)

    stats = result["stats"]
    print("Done.")
    print(f"  history databases     : {stats['history_databases']}")
    print(f"  browser_history records: {stats['browser_history_records']}")
    print(f"  browser_download records: {stats['browser_download_records']}")
    print(f"  total records now      : {len(records)}")
    print(f"  distinct URLs now      : {len(dataset['summary']['identified_urls'])}")
    print(f"  output                 : {args.dataset}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
