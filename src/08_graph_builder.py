"""Build the investigation knowledge graph from the normalized dataset.

Consumes the Phase 1 output (``normalized_dataset.json``) and emits a graph of
correlated entities:

    { "graph_metadata": {...}, "stats": {...}, "nodes": [...], "edges": [...] }

The dataset represents a single Velociraptor collection, so the client / host /
session identity (present only on the context records) is captured once as a
*collection context* and used to anchor the file and user entities that carry
no explicit client or session field of their own.
"""

from __future__ import annotations

import re
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

from . import graph_schema as S
from .graph_model import KnowledgeGraph

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


class CollectionContext:
    """Dataset-level identity shared by evidence lacking explicit IDs."""

    def __init__(self) -> None:
        self.client_id: Optional[str] = None
        self.hostname: Optional[str] = None
        self.session_id: Optional[str] = None

    @property
    def client_node(self) -> Optional[str]:
        """Node id of the collection's client, if known."""
        return S.node_id(S.CLIENT, self.client_id) if self.client_id else None

    @property
    def host_node(self) -> Optional[str]:
        """Node id of the collection's host, if known."""
        return S.node_id(S.HOST, self.hostname) if self.hostname else None

    @property
    def session_node(self) -> Optional[str]:
        """Node id of the collection's session, if known."""
        return S.node_id(S.SESSION, self.session_id) if self.session_id else None


def _discover_context(records: List[Dict[str, Any]]) -> CollectionContext:
    """First pass: capture the single client/host/session identity."""
    context = CollectionContext()
    for record in records:
        ids = record.get("identifiers", {})
        if context.client_id is None and ids.get("client_id"):
            context.client_id = ids["client_id"]
        if context.hostname is None and ids.get("hostname"):
            context.hostname = ids["hostname"]
        if context.session_id is None and ids.get("session_id"):
            context.session_id = ids["session_id"]
    return context


def _file_properties(record: Dict[str, Any]) -> Dict[str, Any]:
    """Pull a small, useful set of properties for a file node."""
    data = record.get("original_data", {})
    path = record.get("path", {})
    return {
        "filename": path.get("filename"),
        "extension": path.get("extension"),
        "drive": path.get("drive"),
        "directory": path.get("directory"),
        "size": data.get("Size") or data.get("FileSize") or data.get("file_size"),
    }


def _add_context_entities(graph: KnowledgeGraph, ctx: CollectionContext) -> None:
    """Ensure the anchor client/host/session nodes and their link exist."""
    if ctx.client_node:
        graph.add_node(ctx.client_node, S.CLIENT, ctx.client_id or "", {})
    if ctx.host_node:
        graph.add_node(ctx.host_node, S.HOST, ctx.hostname or "", {})
    if ctx.session_node:
        graph.add_node(ctx.session_node, S.SESSION, ctx.session_id or "", {})
    if ctx.client_node and ctx.host_node:
        graph.add_edge(ctx.client_node, ctx.host_node, S.IS_HOST)
    if ctx.client_node and ctx.session_node:
        graph.add_edge(ctx.client_node, ctx.session_node, S.RAN)


def _graph_context_record(
    graph: KnowledgeGraph, record: Dict[str, Any], ctx: CollectionContext
) -> None:
    """Add nodes/edges from a client_info / collection_context / request record."""
    ids = record.get("identifiers", {})
    ts = record.get("timestamp")
    rid = record.get("record_id")

    client = S.node_id(S.CLIENT, ids["client_id"]) if ids.get("client_id") else None
    if client:
        graph.add_node(client, S.CLIENT, ids["client_id"], {}, rid, ts)

    if ids.get("hostname"):
        host = S.node_id(S.HOST, ids["hostname"])
        graph.add_node(host, S.HOST, ids["hostname"], {"fqdn": record["original_data"].get("fqdn")}, rid, ts)
        if client:
            graph.add_edge(client, host, S.IS_HOST, rid)

    anchor = client or ctx.client_node
    for raw_ip in _split(ids.get("ip")):
        ip_node = S.node_id(S.IP, raw_ip)
        graph.add_node(ip_node, S.IP, raw_ip, {}, rid, ts)
        if anchor:
            graph.add_edge(anchor, ip_node, S.HAS_IP, rid)
    for raw_mac in _split(ids.get("mac")):
        mac_node = S.node_id(S.MAC, raw_mac)
        graph.add_node(mac_node, S.MAC, raw_mac, {}, rid, ts)
        if anchor:
            graph.add_edge(anchor, mac_node, S.HAS_MAC, rid)

    session = S.node_id(S.SESSION, ids["session_id"]) if ids.get("session_id") else None
    if session:
        graph.add_node(session, S.SESSION, ids["session_id"], {}, rid, ts)
        if client:
            graph.add_edge(client, session, S.RAN, rid)
    if ids.get("request_id") and (session or ctx.session_node):
        req = S.node_id(S.REQUEST, ids["request_id"])
        graph.add_node(req, S.REQUEST, f"request {ids['request_id']}", {}, rid, ts)
        graph.add_edge(session or ctx.session_node, req, S.HAS_REQUEST, rid)

    if ids.get("artifact") and (session or ctx.session_node):
        art = S.node_id(S.ARTIFACT, ids["artifact"])
        graph.add_node(art, S.ARTIFACT, ids["artifact"], {}, rid, ts)
        graph.add_edge(session or ctx.session_node, art, S.COLLECTED_ARTIFACT, rid)


def _graph_file_record(
    graph: KnowledgeGraph, record: Dict[str, Any], ctx: CollectionContext
) -> None:
    """Add nodes/edges from a file_metadata / uploaded_file record."""
    ids = record.get("identifiers", {})
    ts = record.get("timestamp")
    rid = record.get("record_id")
    path = record.get("path", {})

    raw_path = ids.get("file_path")
    if not S.is_valid(raw_path):
        return

    file_node = S.node_id(S.FILE, raw_path)
    graph.add_node(
        file_node,
        S.FILE,
        path.get("filename") or raw_path,
        _file_properties(record),
        rid,
        ts,
    )

    # Owner user (from path or identifier); anchored to the host.
    username = path.get("username") or ids.get("username")
    if S.is_valid(username):
        user_node = S.node_id(S.USER, username)
        graph.add_node(user_node, S.USER, username, {}, rid, ts)
        graph.add_edge(user_node, file_node, S.OWNS, rid)
        if ctx.host_node:
            graph.add_edge(ctx.host_node, user_node, S.HAS_USER, rid)
    else:
        user_node = None

    # File hash.
    if S.is_valid(ids.get("hash")):
        hash_node = S.node_id(S.HASH, ids["hash"])
        graph.add_node(hash_node, S.HASH, ids["hash"][:16], {"algorithm": "sha256"}, rid, ts)
        graph.add_edge(file_node, hash_node, S.HAS_HASH, rid)

    # Owning application.
    application = path.get("application") or ids.get("application")
    if S.is_valid(application):
        app_node = S.node_id(S.APPLICATION, application)
        graph.add_node(app_node, S.APPLICATION, application, {}, rid, ts)
        graph.add_edge(file_node, app_node, S.ASSOCIATED_WITH, rid)
        if user_node:
            graph.add_edge(user_node, app_node, S.USED, rid)

    # Producing artifact and collection session.
    if S.is_valid(ids.get("artifact")):
        art = S.node_id(S.ARTIFACT, ids["artifact"])
        graph.add_node(art, S.ARTIFACT, ids["artifact"], {}, rid, ts)
        graph.add_edge(file_node, art, S.PRODUCED_BY, rid)
    if ctx.session_node:
        graph.add_edge(ctx.session_node, file_node, S.COLLECTED, rid)


def _graph_browser_record(
    graph: KnowledgeGraph, record: Dict[str, Any], ctx: CollectionContext
) -> None:
    """Add nodes/edges from a browser_history / browser_download record."""
    ids = record.get("identifiers", {})
    od = record.get("original_data", {})
    ts = record.get("timestamp")
    rid = record.get("record_id")

    url = ids.get("url") or od.get("url")
    if not S.is_valid(url):
        return

    url_node = S.node_id(S.URL, url)
    graph.add_node(
        url_node, S.URL, url[:80],
        {"full_url": url, "title": od.get("title")}, rid, ts,
    )

    # The user who visited / downloaded it, anchored to the host.
    username = record.get("path", {}).get("username") or ids.get("username")
    user_node = None
    if S.is_valid(username):
        user_node = S.node_id(S.USER, username)
        graph.add_node(user_node, S.USER, username, {}, rid, ts)
        if ctx.host_node:
            graph.add_edge(ctx.host_node, user_node, S.HAS_USER, rid)
        relation = (
            S.DOWNLOADED if record.get("evidence_type") == "browser_download" else S.VISITED
        )
        graph.add_edge(user_node, url_node, relation, rid)

    # A download that landed on disk links the URL to the saved file.
    if record.get("evidence_type") == "browser_download":
        target = ids.get("file_path") or od.get("target_path")
        if S.is_valid(target):
            file_node = S.node_id(S.FILE, target)
            graph.add_node(
                file_node, S.FILE,
                record.get("path", {}).get("filename") or target,
                {"full_path": target}, rid, ts,
            )
            graph.add_edge(url_node, file_node, S.SAVED_AS, rid)
            if user_node:
                graph.add_edge(user_node, file_node, S.OWNS, rid)


def _iter_strings(value: Any) -> Iterable[str]:
    """Recursively yield every string inside a JSON-like value."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for child in value.values():
            yield from _iter_strings(child)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _iter_strings(item)


def _graph_cves(
    graph: KnowledgeGraph, records: List[Dict[str, Any]], ctx: CollectionContext
) -> None:
    """Add CVE nodes, linked to the collection context that references them.

    A CVE identifier present in the data becomes a node; the edge only records
    *that the collection referenced it* (REFERENCES_CVE) - it does not assert a
    link to any particular download, which the raw data does not establish.
    """
    anchor = ctx.session_node or ctx.client_node or ctx.host_node
    for record in records:
        cves = set()
        cve_id = record.get("identifiers", {}).get("cve")
        if cve_id:
            cves.add(cve_id.upper())
        if record.get("evidence_type") in _CVE_SCAN_EVIDENCE:
            for text in _iter_strings(record.get("original_data", {})):
                for match in _CVE_RE.findall(text):
                    cves.add(match.upper())
        for cve in cves:
            cve_node = S.node_id(S.CVE, cve)
            graph.add_node(cve_node, S.CVE, cve, {}, record.get("record_id"),
                           record.get("timestamp"))
            if anchor:
                graph.add_edge(anchor, cve_node, S.REFERENCES_CVE, record.get("record_id"))


def _split(value: Optional[str]) -> List[str]:
    """Split a comma-joined identifier string into individual values."""
    if not value:
        return []
    return [part.strip() for part in value.split(",") if part.strip()]


_FILE_EVIDENCE = {"file_metadata", "uploaded_file"}
_CONTEXT_EVIDENCE = {"client_info", "collection_context", "flow_request"}
_BROWSER_EVIDENCE = {"browser_history", "browser_download"}
_CVE_SCAN_EVIDENCE = {"flow_request", "client_info", "collection_context"}


def build_graph(dataset: Dict[str, Any]) -> Dict[str, Any]:
    """Build the full knowledge graph from a Phase 1 dataset dictionary."""
    records: List[Dict[str, Any]] = dataset.get("normalized_records", [])
    graph = KnowledgeGraph()

    context = _discover_context(records)
    _add_context_entities(graph, context)

    for record in records:
        evidence_type = record.get("evidence_type")
        if evidence_type in _FILE_EVIDENCE:
            _graph_file_record(graph, record, context)
        elif evidence_type in _CONTEXT_EVIDENCE:
            _graph_context_record(graph, record, context)
        elif evidence_type in _BROWSER_EVIDENCE:
            _graph_browser_record(graph, record, context)
        # log_entry / generic records carry no correlatable entities.

    _graph_cves(graph, records, context)
    return _assemble(graph, dataset, context)


def _assemble(
    graph: KnowledgeGraph, dataset: Dict[str, Any], context: CollectionContext
) -> Dict[str, Any]:
    """Serialize the graph and compute summary statistics."""
    nodes = graph.nodes
    edges = graph.edges

    metadata = {
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "phase": "Phase 2 - Knowledge Graph",
        "source_dataset_records": dataset.get("summary", {}).get("num_records"),
        "collection_context": {
            "client_id": context.client_id,
            "hostname": context.hostname,
            "session_id": context.session_id,
        },
        "entity_types": sorted({n.type for n in nodes}),
        "relationship_types": sorted({e.type for e in edges}),
    }

    stats = _compute_stats(graph)

    return {
        "graph_metadata": metadata,
        "stats": stats,
        "nodes": [n.as_dict() for n in nodes],
        "edges": [e.as_dict() for e in edges],
    }


def _compute_stats(graph: KnowledgeGraph) -> Dict[str, Any]:
    """Compute node/edge counts and a few investigative leaderboards."""
    nodes = graph.nodes
    edges = graph.edges

    nodes_by_type = Counter(n.type for n in nodes)
    edges_by_type = Counter(e.type for e in edges)

    files_per_user: Counter = Counter()
    files_per_app: Counter = Counter()
    label_by_id = {n.id: n.label for n in nodes}
    for edge in edges:
        if edge.type == S.OWNS:
            files_per_user[label_by_id.get(edge.source, edge.source)] += 1
        elif edge.type == S.ASSOCIATED_WITH:
            files_per_app[label_by_id.get(edge.target, edge.target)] += 1

    extensions = Counter(
        n.properties.get("extension")
        for n in nodes
        if n.type == S.FILE and n.properties.get("extension")
    )

    return {
        "total_nodes": len(nodes),
        "total_edges": len(edges),
        "nodes_by_type": dict(sorted(nodes_by_type.items())),
        "edges_by_type": dict(sorted(edges_by_type.items())),
        "top_users_by_files": files_per_user.most_common(10),
        "top_applications_by_files": files_per_app.most_common(10),
        "top_file_extensions": extensions.most_common(15),
        "unique_hashes": nodes_by_type.get(S.HASH, 0),
        "unique_files": nodes_by_type.get(S.FILE, 0),
    }
