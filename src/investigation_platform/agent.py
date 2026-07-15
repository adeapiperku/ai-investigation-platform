"""Grounded query tools an AI agent (or a human) can call to answer
investigation questions.

Design principle: every function here returns data pulled directly from
the normalized dataset / knowledge graph / anomaly report, plus the
provenance behind it. Nothing is summarized or guessed at this layer.
An LLM can sit on top of these as function-calling "tools" - it composes
and phrases the answer, but every fact in that answer must trace back to
one of these function results. If a question can't be answered from the
tools below, the correct response is "the data doesn't show that",
not a guess.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

import networkx as nx

from .graph import build_graph, extract_user
from .evtx_parser import parse_logon_events, resolve_upload_path
from .browser_history import read_history, resolve_edge_history_path

# Internal/corporate domain seen across all users - not evidence of anything
# suspicious on its own, so it's filtered out of "external sites visited".
INTERNAL_DOMAINS = ("app01.tridsk.local",)


class InvestigationAgent:
    def __init__(self, case_root: Path, normalized_dir: Path, reports_dir: Path):
        self.case_root = Path(case_root)
        self.normalized_dir = Path(normalized_dir)
        self.reports_dir = Path(reports_dir)
        self.graph: nx.DiGraph = build_graph(self.case_root, self.normalized_dir)

        with (self.reports_dir / "anomalies.json").open("r", encoding="utf-8") as fh:
            self.anomalies = json.load(fh)

        with (self.case_root / "client_info.json").open("r", encoding="utf-8") as fh:
            self.client_info = json.load(fh)

    # ---- tools -----------------------------------------------------

    def endpoint_info(self) -> dict[str, Any]:
        """Report the endpoint machine and the collection agent that ran on it
        (hostname, OS, and the name/version of the forensic collection agent
        installed - e.g. Velociraptor)."""
        ci = self.client_info
        return {
            "answer": {
                "hostname": ci.get("hostname"),
                "fqdn": ci.get("fqdn"),
                "os": ci.get("system"),
                "os_release": ci.get("release"),
                "architecture": ci.get("architecture"),
                "collection_agent_name": ci.get("client_name"),
                "collection_agent_version": ci.get("client_version"),
            },
            "source": "client_info.json",
        }

    def list_users(self) -> dict[str, Any]:
        """List every real user profile found on the host."""
        users = [
            data["username"]
            for _, data in self.graph.nodes(data=True)
            if data.get("kind") == "user"
        ]
        return {
            "answer": sorted(users),
            "source": "knowledge graph (user nodes), derived from normalized file paths",
        }

    def files_by_user(self, username: str) -> dict[str, Any]:
        """List files owned by a given user's profile, with provenance."""
        user_node = f"user:{username}"
        if not self.graph.has_node(user_node):
            return {"answer": [], "note": f"no profile found for '{username}'", "source": None}
        files = []
        for _, file_node in self.graph.out_edges(user_node):
            data = self.graph.nodes[file_node]
            if data.get("kind") != "file":
                continue
            files.append(
                {
                    "path": file_node,
                    "size": data.get("size"),
                    "modified": data.get("modified"),
                    "provenance": data.get("provenance"),
                }
            )
        return {"answer": files, "count": len(files), "source": "knowledge graph edges user->file"}

    def file_lookup(self, path_substring: str) -> dict[str, Any]:
        """Find files whose path contains the given substring."""
        matches = []
        for node, data in self.graph.nodes(data=True):
            if data.get("kind") == "file" and path_substring.lower() in node.lower():
                matches.append({"path": node, **{k: v for k, v in data.items() if k != "kind"}})
        return {"answer": matches, "count": len(matches), "source": "normalized files.jsonl"}

    def collection_completeness(self) -> dict[str, Any]:
        """Report how complete the collection was (expected vs actual bytes)."""
        totals = self.anomalies["collection_totals"]
        return {"answer": totals, "source": "collection_context.json (via anomalies.json)"}

    def size_mismatches(self, limit: Optional[int] = 20) -> dict[str, Any]:
        """List files whose collected size didn't match the expected size."""
        items = self.anomalies["size_mismatches"]
        return {
            "answer": items[:limit] if limit else items,
            "total_count": len(items),
            "source": "data/reports/anomalies.json:size_mismatches",
        }

    def log_problems(self) -> dict[str, Any]:
        """List any non-default-level log lines from the collection run."""
        return {
            "answer": self.anomalies["log_problems"],
            "source": "log.json (via anomalies.json)",
        }

    def anomaly_summary(self) -> dict[str, Any]:
        """High-level counts of every anomaly category detected."""
        return {"answer": self.anomalies["summary"], "source": "data/reports/anomalies.json"}

    def logon_events(self, username: Optional[str] = None) -> dict[str, Any]:
        """List Windows logon events (Event ID 4624) from Security.evtx,
        optionally filtered to one domain user. System/service account
        logons are excluded when no username is given."""
        evtx_path = resolve_upload_path(self.case_root, r"C:\Windows\System32\winevt\Logs\Security.evtx")
        if not evtx_path.exists():
            return {"answer": [], "note": "Security.evtx not found in this collection", "source": None}
        events = parse_logon_events(evtx_path, username)
        return {
            "answer": events,
            "count": len(events),
            "source": "Security.evtx (Event ID 4624), parsed from uploads/",
        }

    def browsing_history(self, username: str) -> dict[str, Any]:
        """List URLs visited by a given user, from their Edge History file."""
        history_path = resolve_edge_history_path(self.case_root, username)
        if not history_path.exists():
            return {"answer": [], "note": f"no Edge History file found for '{username}'", "source": None}
        entries = read_history(history_path)
        return {
            "answer": entries,
            "count": len(entries),
            "source": f"Edge History SQLite file for {username}, parsed from uploads/",
        }

    def external_urls_visited(self) -> dict[str, Any]:
        """List all non-internal (non-app01.tridsk.local) URLs visited by
        any user on this host, across all their Edge History files. Useful
        for spotting a suspicious/external site a user visited, since it
        doesn't require knowing which user in advance."""
        results = []
        for _, data in self.graph.nodes(data=True):
            if data.get("kind") != "user":
                continue
            username = data["username"]
            history_path = resolve_edge_history_path(self.case_root, username)
            if not history_path.exists():
                continue
            for entry in read_history(history_path):
                url = entry.get("url") or ""
                if any(dom in url for dom in INTERNAL_DOMAINS):
                    continue
                results.append({"username": username, **entry})
        results.sort(key=lambda e: e.get("last_visit_time_utc") or "", reverse=True)
        return {
            "answer": results,
            "count": len(results),
            "source": "Edge History SQLite files for all users, parsed from uploads/ (internal app01.tridsk.local URLs excluded)",
        }


# ---- a minimal keyword-based router --------------------------------
#
# This is NOT a substitute for a real LLM agent. It's a placeholder
# dispatcher so the tools above can be exercised end-to-end without an
# API key configured. In production, an LLM (e.g. Claude) should be
# given these methods as function-calling tools and choose which to
# call based on the natural-language question; the grounding guarantee
# (every claim traces to a tool result) holds either way.


def answer(agent: InvestigationAgent, question: str) -> dict[str, Any]:
    q = question.lower()
    if any(kw in q for kw in ("agent installed", "collection agent", "velociraptor", "hostname", "endpoint", "what os", "operating system")):
        return agent.endpoint_info()
    if "how complete" in q or "expected" in q and "byte" in q:
        return agent.collection_completeness()
    if "user" in q and ("list" in q or "who" in q or "which users" in q):
        return agent.list_users()
    if any(kw in q for kw in ("log into", "logged in", "logon", "log on", "logged into")):
        for _, data in agent.graph.nodes(data=True):
            if data.get("kind") == "user" and data["username"].lower() in q:
                return agent.logon_events(data["username"])
        return agent.logon_events()
    if any(kw in q for kw in ("url", "repository", "repo", "downloaded", "malicious site", "visited")):
        for _, data in agent.graph.nodes(data=True):
            if data.get("kind") == "user" and data["username"].lower() in q:
                return agent.browsing_history(data["username"])
        return agent.external_urls_visited()
    for _, data in agent.graph.nodes(data=True):
        if data.get("kind") == "user" and data["username"].lower() in q:
            return agent.files_by_user(data["username"])
    if "mismatch" in q or "truncat" in q or "partial" in q:
        return agent.size_mismatches()
    if "log" in q and ("error" in q or "problem" in q or "warn" in q):
        return agent.log_problems()
    if "anomal" in q or "summary" in q:
        return agent.anomaly_summary()
    return {
        "answer": None,
        "note": "No tool matched this question; the data doesn't show an answer for it without a more specific query.",
        "source": None,
    }


if __name__ == "__main__":
    import sys

    case_root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(
        "TriDsk-WKS02-C.1dfcd21bd3d01cc0-F.D3JVHAK4B16NM"
    )
    normalized_dir = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("data/normalized")
    reports_dir = Path(sys.argv[3]) if len(sys.argv) > 3 else Path("data/reports")
    question = sys.argv[4] if len(sys.argv) > 4 else "How complete was the collection?"

    agent = InvestigationAgent(case_root, normalized_dir, reports_dir)
    result = answer(agent, question)
    print(json.dumps(result, indent=2, default=str))
