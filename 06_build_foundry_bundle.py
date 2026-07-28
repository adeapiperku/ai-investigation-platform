# python 06_build_foundry_bundle.py
"""Step 6: assemble the upload set for an Azure AI Foundry agent.

Usage:
    python 06_build_foundry_bundle.py [--normalized DIR] [--out DIR]

Writes ``data/foundry_upload/`` — one JSON file per dataset, sized for a
file-search index, plus ``_manifest.json`` describing what each file holds and
which questions it bears on, and a copy of ``QUESTIONS.md``.

Upload **every file in that directory** to the agent's vector store. The bulk
datasets are reduced to the investigation-relevant subset; each reduced file
states how many records were dropped and by what rule, so the agent is never
led to treat a filtered file as complete.
"""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

from src.foundry_bundle import SOFT_SIZE_LIMIT_MB, build_bundle, build_csv_bundle
from src.normalized_loader import dataset_files

DEFAULT_NORMALIZED = Path("data/normalized")
DEFAULT_OUT = Path("data/foundry_upload")
DEFAULT_CSV_OUT = Path("data/foundry_upload_csv")
QUESTIONS = Path("QUESTIONS.md")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="Build the Azure AI Foundry upload set")
    parser.add_argument("--normalized", type=Path, default=DEFAULT_NORMALIZED)
    parser.add_argument("--out", type=Path, default=None)
    parser.add_argument(
        "--csv",
        action="store_true",
        help=(
            "emit complete, unfiltered CSVs for the code_interpreter tool "
            "instead of reduced JSON for file search"
        ),
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Build the bundle and print exactly what to upload."""
    args = parse_args(argv)
    out_dir = args.out or (DEFAULT_CSV_OUT if args.csv else DEFAULT_OUT)

    if not args.normalized.is_dir() or not dataset_files(args.normalized):
        print(
            f"error: no normalized datasets in {args.normalized}\n"
            "run normalization first:  python 01_normalize_datasets.py",
            file=sys.stderr,
        )
        return 1

    tool = "code_interpreter (complete CSVs)" if args.csv else "file_search (reduced JSON)"
    print(f"Building Foundry upload set for {tool} from {args.normalized} ...\n")
    manifest = (
        build_csv_bundle(args.normalized, out_dir)
        if args.csv
        else build_bundle(args.normalized, out_dir)
    )

    if QUESTIONS.is_file():
        shutil.copy(QUESTIONS, out_dir / QUESTIONS.name)

    print(f"{'file':<32}{'records':>9}{'MB':>8}  questions")
    print("-" * 68)
    for entry in manifest["files"]:
        questions = ", ".join(f"Q{n}" for n in entry["answers_questions"]) or "-"
        flag = "  <-- large" if entry.get("over_soft_limit") else ""
        print(
            f"{entry['file']:<32}{entry['records']:>9}{entry['size_mb']:>8.2f}"
            f"  {questions}{flag}"
        )
    print("-" * 68)
    print(f"{'total':<32}{'':>9}{manifest['total_size_mb']:>8.2f}")

    oversized = [e["file"] for e in manifest["files"] if e.get("over_soft_limit")]
    if oversized:
        print(
            f"\nnote: {', '.join(oversized)} exceed the {SOFT_SIZE_LIMIT_MB:g} MB soft "
            "limit. They will still index, but expect slower ingestion."
        )

    target_tool = "code interpreter" if args.csv else "vector store"
    print(f"\nUpload every file in {out_dir} to the agent's {target_tool}:")
    for path in sorted(out_dir.iterdir()):
        print(f"  {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
