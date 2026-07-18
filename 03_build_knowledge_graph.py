# python 03_build_knowledge_graph.py
"""Phase 2 entry point: build the investigation knowledge graph.

Usage:
    python 03_build_knowledge_graph.py [--dataset FILE] [--out FILE]

Reads the Phase 1 normalized dataset and writes
``data/processed/knowledge_graph.json``.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from src.graph_builder import build_graph

DEFAULT_DATASET = Path("data/processed/normalized_dataset.json")
DEFAULT_OUT = Path("data/processed/knowledge_graph.json")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="Phase 2 knowledge-graph builder")
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Load the dataset, build the graph and write it to disk."""
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
