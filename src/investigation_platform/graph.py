"""Build a knowledge graph from the normalized file records.

Nodes: host, users, files, source artifacts.
Edges: host -[has_profile]-> user, user -[owns]-> file,
       file -[collected_by]-> artifact.

The graph only encodes relationships that are directly derivable from
the normalized data (mainly: whose Windows profile a file path sits
under). It does not infer anything about intent or behavior - that is
left to the AI agent step, which must cite back to these nodes/edges.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Optional

import networkx as nx

USER_PATH_RE = re.compile(r"^[A-Za-z]:\\Users\\([^\\]+)\\", re.IGNORECASE)


def extract_user(path: str) -> Optional[str]:
    m = USER_PATH_RE.match(path)
    if not m:
        return None
    user = m.group(1)
    # Skip non-personal profile folders.
    if user.lower() in ("public", "default", "defaultuser0", "all users"):
        return None
    return user


def _load_normalized(normalized_dir: Path) -> list[dict[str, Any]]:
    path = normalized_dir / "files.jsonl"
    with path.open("r", encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def build_graph(case_root: Path, normalized_dir: Path) -> nx.DiGraph:
    client_info_path = case_root / "client_info.json"
    with client_info_path.open("r", encoding="utf-8") as fh:
        client_info = json.load(fh)
    hostname = client_info.get("hostname", "UNKNOWN_HOST")

    files = _load_normalized(normalized_dir)

    g = nx.DiGraph()
    g.add_node(hostname, kind="host")

    for f in files:
        file_node = f["path"]
        g.add_node(
            file_node,
            kind="file",
            size=f.get("size"),
            sha256=f.get("sha256"),
            created=f.get("created"),
            modified=f.get("modified"),
            last_accessed=f.get("last_accessed"),
            provenance=f["provenance"],
        )

        user = extract_user(f["path"])
        if user:
            user_node = f"user:{user}"
            if not g.has_node(user_node):
                g.add_node(user_node, kind="user", username=user)
                g.add_edge(hostname, user_node, relation="has_profile")
            g.add_edge(user_node, file_node, relation="owns")

        for prov in f["provenance"]:
            artifact_node = f"artifact:{prov['source_file']}"
            if not g.has_node(artifact_node):
                g.add_node(artifact_node, kind="artifact")
            g.add_edge(file_node, artifact_node, relation="collected_by")

    return g


def graph_stats(g: nx.DiGraph) -> dict[str, Any]:
    kinds: dict[str, int] = {}
    for _, data in g.nodes(data=True):
        kind = data.get("kind", "unknown")
        kinds[kind] = kinds.get(kind, 0) + 1
    users = [
        data["username"]
        for _, data in g.nodes(data=True)
        if data.get("kind") == "user"
    ]
    return {
        "total_nodes": g.number_of_nodes(),
        "total_edges": g.number_of_edges(),
        "nodes_by_kind": kinds,
        "users_found": sorted(users),
    }


def write_graph(case_root: Path, normalized_dir: Path, out_dir: Path) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    g = build_graph(case_root, normalized_dir)

    graphml_path = out_dir / "knowledge_graph.graphml"
    # GraphML can't store list/dict attrs (e.g. provenance); strip those.
    g_export = g.copy()
    for _, data in g_export.nodes(data=True):
        for key in list(data):
            if isinstance(data[key], (list, dict)):
                data[key] = json.dumps(data[key])
            elif data[key] is None:
                del data[key]
    nx.write_graphml(g_export, graphml_path)

    stats = graph_stats(g)
    stats_path = out_dir / "graph_stats.json"
    with stats_path.open("w", encoding="utf-8") as fh:
        json.dump(stats, fh, indent=2)

    return stats


if __name__ == "__main__":
    import sys

    case_root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(
        "TriDsk-WKS02-C.1dfcd21bd3d01cc0-F.D3JVHAK4B16NM"
    )
    normalized_dir = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("data/normalized")
    out_dir = Path(sys.argv[3]) if len(sys.argv) > 3 else Path("data/graph")
    stats = write_graph(case_root, normalized_dir, out_dir)
    print(json.dumps(stats, indent=2))
