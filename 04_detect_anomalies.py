# python 04_detect_anomalies.py
"""Phase 4 entry point: clean the dataset and detect anomalies.

Usage:
    python 04_detect_anomalies.py [--dataset FILE] [--out FILE]

Reads the Phase 1 normalized dataset, removes duplicate records, flags
anomalies and surfaces investigation leads (URLs, CVEs, possible logon
evidence), then writes ``data/processed/cleaned_dataset.json``.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from src.anomaly_detector import analyze

DEFAULT_DATASET = Path("data/processed/normalized_dataset.json")
DEFAULT_OUT = Path("data/processed/cleaned_dataset.json")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="Phase 3 cleaning & anomaly detection")
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Load the dataset, clean/analyze it and write the result to disk."""
    args = parse_args(argv)

    if not args.dataset.exists():
        print(
            f"error: normalized dataset not found: {args.dataset}\n"
            "run Phase 1 first:  python 01_build_dataset.py",
            file=sys.stderr,
        )
        return 1

    print(f"Loading {args.dataset} ...")
    with args.dataset.open(encoding="utf-8") as handle:
        dataset = json.load(handle)

    print("Cleaning dataset and detecting anomalies ...")
    cleaned = analyze(dataset)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8") as handle:
        json.dump(cleaned, handle, indent=2, ensure_ascii=False, default=str)

    summary = cleaned["anomaly_summary"]
    leads = cleaned["investigation_leads"]
    agent = leads["incident_response_agent"]
    print("Done.")
    print(f"  input records        : {summary['input_records']}")
    print(f"  duplicates removed    : {summary['duplicate_records_removed']}")
    print(f"  cleaned records       : {summary['cleaned_records']}")
    print(f"  records w/ anomalies  : {summary['records_with_anomalies']}")
    print(f"  anomaly flags         : {summary['anomaly_flag_counts']}")
    print(f"  IR agent (Q1)         : {agent['name'] if agent else None} "
          f"{agent['version'] if agent else ''}")
    print(f"  URL leads             : {len(leads['urls'])}")
    print(f"  CVE leads             : {len(leads['cves'])}")
    print(f"  output                : {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
