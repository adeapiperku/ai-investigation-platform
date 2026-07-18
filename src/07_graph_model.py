"""In-memory knowledge-graph model with node/edge de-duplication.

Nodes and edges are merged on a stable id so the same entity referenced by
thousands of records collapses to one node. Evidence is tracked as a count plus
a bounded sample of contributing ``record_id`` values (to keep output small).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

# Maximum number of contributing record ids stored per node/edge.
EVIDENCE_SAMPLE_LIMIT = 20


@dataclass
class Node:
    """A single graph entity (host, user, file, hash, application, ...)."""

    id: str
    type: str
    label: str
    properties: Dict[str, Any] = field(default_factory=dict)
    evidence_count: int = 0
    evidence_sample: List[str] = field(default_factory=list)
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None

    def as_dict(self) -> Dict[str, Any]:
        """Return a JSON-serializable representation of the node."""
        return {
            "id": self.id,
            "type": self.type,
            "label": self.label,
            "properties": self.properties,
            "evidence_count": self.evidence_count,
            "evidence_sample": self.evidence_sample,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
        }


@dataclass
class Edge:
    """A directed, typed relationship between two nodes."""

    id: str
    source: str
    target: str
    type: str
    properties: Dict[str, Any] = field(default_factory=dict)
    weight: int = 0
    evidence_sample: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        """Return a JSON-serializable representation of the edge."""
        return {
            "id": self.id,
            "source": self.source,
            "target": self.target,
            "type": self.type,
            "properties": self.properties,
            "weight": self.weight,
            "evidence_sample": self.evidence_sample,
        }


def _extend_seen(current: Optional[str], candidate: Optional[str], newest: bool) -> Optional[str]:
    """Return the earliest/latest of two ISO timestamps (string-comparable)."""
    if candidate is None:
        return current
    if current is None:
        return candidate
    if newest:
        return max(current, candidate)
    return min(current, candidate)


class KnowledgeGraph:
    """A de-duplicating container of nodes and edges."""

    def __init__(self) -> None:
        self._nodes: Dict[str, Node] = {}
        self._edges: Dict[str, Edge] = {}

    # -- nodes ------------------------------------------------------------- #

    def add_node(
        self,
        node_id: str,
        node_type: str,
        label: str,
        properties: Optional[Dict[str, Any]] = None,
        record_id: Optional[str] = None,
        timestamp: Optional[str] = None,
    ) -> str:
        """Create or merge a node and return its id.

        Repeated calls for the same ``node_id`` accumulate evidence, union the
        properties (first non-empty value wins) and widen the seen-time window.
        """
        node = self._nodes.get(node_id)
        if node is None:
            node = Node(id=node_id, type=node_type, label=label)
            self._nodes[node_id] = node

        if properties:
            for key, value in properties.items():
                if value in (None, "", [], {}):
                    continue
                node.properties.setdefault(key, value)

        node.evidence_count += 1
        if record_id and len(node.evidence_sample) < EVIDENCE_SAMPLE_LIMIT:
            node.evidence_sample.append(record_id)
        node.first_seen = _extend_seen(node.first_seen, timestamp, newest=False)
        node.last_seen = _extend_seen(node.last_seen, timestamp, newest=True)
        return node_id

    # -- edges ------------------------------------------------------------- #

    def add_edge(
        self,
        source: str,
        target: str,
        edge_type: str,
        record_id: Optional[str] = None,
        properties: Optional[Dict[str, Any]] = None,
    ) -> Optional[str]:
        """Create or merge a directed edge and return its id.

        Edges are keyed on ``(source, type, target)`` so parallel evidence for
        the same relationship increases the edge weight instead of duplicating.
        Self-loops and edges with a missing endpoint are ignored.
        """
        if not source or not target or source == target:
            return None
        edge_id = f"{source}|{edge_type}|{target}"
        edge = self._edges.get(edge_id)
        if edge is None:
            edge = Edge(id=edge_id, source=source, target=target, type=edge_type)
            self._edges[edge_id] = edge

        if properties:
            for key, value in properties.items():
                if value not in (None, "", [], {}):
                    edge.properties.setdefault(key, value)

        edge.weight += 1
        if record_id and len(edge.evidence_sample) < EVIDENCE_SAMPLE_LIMIT:
            edge.evidence_sample.append(record_id)
        return edge_id

    # -- access ------------------------------------------------------------ #

    def has_node(self, node_id: str) -> bool:
        """Return whether a node with ``node_id`` exists."""
        return node_id in self._nodes

    @property
    def nodes(self) -> List[Node]:
        """All nodes currently in the graph."""
        return list(self._nodes.values())

    @property
    def edges(self) -> List[Edge]:
        """All edges currently in the graph."""
        return list(self._edges.values())
