# python src/03_extractors.py
"""Extraction of correlation identifiers, timestamps and evidence types.

These helpers turn a raw source record into the normalized fields that later
phases (graph construction, AI investigation) will correlate on.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from .normalizers import normalize_path, normalize_timestamp

# --------------------------------------------------------------------------- #
# Field name mappings
# --------------------------------------------------------------------------- #

# Raw record keys grouped by the normalized identifier they map to.
# Comparison is case-insensitive.
_IDENTIFIER_KEYS: Dict[str, List[str]] = {
    "client_id": ["client_id", "clientid"],
    "hostname": ["hostname", "host", "fqdn", "computer_name"],
    "session_id": ["session_id", "sessionid"],
    "flow_id": ["flow_id", "flowid", "last_interrogate_flow_id"],
    "request_id": ["request_id", "requestid"],
    "username": ["username", "user", "user_name"],
    "url": ["url", "uri", "link"],
    "process": ["process", "process_name", "exe", "image"],
    "pid": ["pid", "process_id"],
    "hash": ["hash", "sha256", "sha1", "md5", "sourcefilesha256"],
    "file_path": ["sourcefile", "vfs_path", "path", "filename", "destinationfile"],
    "artifact": ["artifact", "_source", "last_interrogate_artifact_name"],
    "application": ["application", "app", "client_name"],
    "ip": ["ip_address", "ip", "src_ip", "dest_ip", "addr"],
    "mac": ["mac_addresses", "mac", "mac_address"],
    "domain": ["domain", "dns", "hostname_domain"],
    "cve": ["cve", "cve_id", "vulnerability"],
}

# Candidate timestamp field names, ordered by preference.
_TIMESTAMP_KEYS = [
    "timestamp",
    "Timestamp",
    "client_time",
    "started",
    "CopiedOnTimestamp",
    "create_time",
    "start_time",
    "active_time",
    "Created",
    "Modified",
    "Changed",
    "first_seen_at",
    "ping",
    "time",
]

_IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def _lower_key_index(record: Dict[str, Any]) -> Dict[str, str]:
    """Map lowercased keys back to their original keys for lookup."""
    return {k.lower(): k for k in record.keys()}


def _stringify(value: Any) -> Optional[str]:
    """Return a compact string form of a scalar/list value, or ``None``."""
    if value is None:
        return None
    if isinstance(value, (list, tuple)):
        parts = [_stringify(v) for v in value]
        parts = [p for p in parts if p]
        return ", ".join(parts) if parts else None
    if isinstance(value, bool):
        return None
    if isinstance(value, (str, int, float)):
        text = str(value).strip()
        return text or None
    return None


def extract_identifiers(record: Dict[str, Any]) -> Dict[str, str]:
    """Extract normalized correlation identifiers from a record.

    Values are pulled from known keys, then enriched with identifiers derived
    from any file path present in the record (username, drive-based hints).
    """
    identifiers: Dict[str, str] = {}
    key_index = _lower_key_index(record)

    for norm_name, candidates in _IDENTIFIER_KEYS.items():
        for candidate in candidates:
            original_key = key_index.get(candidate.lower())
            if original_key is None:
                continue
            value = _stringify(record[original_key])
            if value:
                identifiers[norm_name] = value
                break

    # Derive extra identifiers from a file path when available.
    raw_path = identifiers.get("file_path")
    if raw_path:
        path_parts = normalize_path(raw_path)
        if path_parts["username"] and "username" not in identifiers:
            identifiers["username"] = path_parts["username"]
        if path_parts["application"] and "application" not in identifiers:
            identifiers["application"] = path_parts["application"]

    # Normalize IP (strip any port) and scan free-text for CVEs.
    if "ip" in identifiers:
        ip_match = _IP_RE.search(identifiers["ip"])
        if ip_match:
            identifiers["ip"] = ip_match.group(0)

    cve = _find_cve(record)
    if cve:
        identifiers["cve"] = cve

    return identifiers


def _find_cve(record: Dict[str, Any]) -> Optional[str]:
    """Search string values for a CVE identifier."""
    for value in record.values():
        if isinstance(value, str):
            match = _CVE_RE.search(value)
            if match:
                return match.group(0).upper()
    return None


def extract_timestamp(record: Dict[str, Any]) -> Optional[str]:
    """Find and normalize the most relevant timestamp in a record."""
    key_index = _lower_key_index(record)
    for candidate in _TIMESTAMP_KEYS:
        original_key = key_index.get(candidate.lower())
        if original_key is None:
            continue
        normalized = normalize_timestamp(record[original_key])
        if normalized:
            return normalized
    return None


# Mapping from Velociraptor artifact sources to concise evidence types.
_SOURCE_EVIDENCE = {
    "all matches metadata": "file_metadata",
    "all file metadata": "file_metadata",
    "uploads": "uploaded_file",
    "basicinformation": "client_info",
}


def classify_evidence(record: Dict[str, Any], source_file: str) -> str:
    """Determine a stable ``evidence_type`` for a record.

    Uses the artifact ``_Source`` field when present, otherwise falls back to
    the source file name.
    """
    source = record.get("_Source") or record.get("_source")
    if isinstance(source, str):
        tail = source.split("/")[-1].strip().lower()
        for hint, evidence in _SOURCE_EVIDENCE.items():
            if hint in tail:
                return evidence

    stem = Path(source_file).name.lower()
    if "client_info" in stem:
        return "client_info"
    if "collection_context" in stem:
        return "collection_context"
    if stem.startswith("log"):
        return "log_entry"
    if "request" in stem:
        return "flow_request"
    if "upload" in stem:
        return "uploaded_file"
    if "metadata" in stem:
        return "file_metadata"
    return "generic"
