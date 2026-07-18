# python 01_build_dataset.py
"""Phase 1 entry point: build the normalized investigation dataset.

Usage:
    python 01_build_dataset.py [--raw DIR] [--out FILE]

Reads every JSON/JSONL file under ``data/raw`` (recursively), normalizes and
correlates the records, and writes ``data/processed/normalized_dataset.json``.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from src.dataset_builder import build_dataset

DEFAULT_RAW = Path("data/raw")
DEFAULT_OUT = Path("data/processed/normalized_dataset.json")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="Phase 1 data normalization pipeline")
    parser.add_argument(
        "--raw", type=Path, default=DEFAULT_RAW, help="raw data directory"
    )
    parser.add_argument(
        "--out", type=Path, default=DEFAULT_OUT, help="output JSON file path"
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Run the pipeline and write the normalized dataset to disk."""
    args = parse_args(argv)

    if not args.raw.exists():
        print(f"error: raw data directory not found: {args.raw}", file=sys.stderr)
        return 1

    print(f"Scanning {args.raw} ...")
    dataset = build_dataset(args.raw)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8") as handle:
        json.dump(dataset, handle, indent=2, ensure_ascii=False, default=str)

    summary = dataset["summary"]
    print("Done.")
    print(f"  source files : {summary['num_source_files']}")
    print(f"  records      : {summary['num_records']}")
    print(f"  users        : {len(summary['identified_users'])}")
    print(f"  hosts        : {len(summary['identified_hosts'])}")
    print(f"  applications : {len(summary['identified_applications'])}")
    print(f"  collection issues: {summary['total_collection_issues']}")
    print(f"  output       : {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
