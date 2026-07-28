# python 02_build_knowledge_graph.py
"""Phase 2 entry point: build the investigation knowledge graph.

Usage:
    python 02_build_knowledge_graph.py [--normalized DIR] [--out FILE]
                                       [--only DATASET ...]

Reads the per-dataset normalized files, combines them **in memory only**, and
writes ``data/processed/knowledge_graph.json``. Use ``--only`` to graph a
subset of the datasets.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from src.graph_builder import build_graph
from src.normalized_loader import load_normalized, require_normalized

DEFAULT_NORMALIZED = Path("data/normalized")
DEFAULT_OUT = Path("data/processed/knowledge_graph.json")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="Phase 2 knowledge-graph builder")
    parser.add_argument("--normalized", type=Path, default=DEFAULT_NORMALIZED)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--only", nargs="+", metavar="DATASET")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Load the normalized datasets, build the graph and write it to disk."""
    args = parse_args(argv)

    print(f"Loading normalized datasets from {args.normalized} ...")
    try:
        dataset = (
            load_normalized(args.normalized, only=args.only)
            if args.only
            else require_normalized(args.normalized)
        )
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    meta = dataset["dataset_metadata"]
    print(
        f"  {meta['num_datasets']} dataset(s), "
        f"{len(dataset['normalized_records'])} records"
    )
    print("Building knowledge graph ...")
    graph = build_graph(dataset)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8") as handle:
        json.dump(graph, handle, indent=2, ensure_ascii=False, default=str)

    stats = graph["stats"]
    print("Done.")
    print(f"  nodes : {stats['total_nodes']}")
    print(f"  edges : {stats['total_edges']}")
    print(f"  by type (nodes): {stats['nodes_by_type']}")
    print(f"  by type (edges): {stats['edges_by_type']}")
    print(f"  output: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
