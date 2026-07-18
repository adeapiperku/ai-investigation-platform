"""Dataset cleaning and anomaly detection (Phase 3).

Consumes the Phase 1 normalized dataset and:

1. **Cleans** it by removing exact duplicate records (same original payload
   within one source file) so downstream steps work on de-duplicated evidence.
2. **Flags anomalies** on each surviving record (zero-byte file, incomplete
   upload, missing timestamp, remote-access tooling, suspicious executable in a
   user profile).
3. **Surfaces investigation leads** by deep-scanning every record's
   ``original_data`` for URLs and CVE identifiers (the Phase 1 extractor only
   looks at top-level keys, so nested values were missed). Every lead keeps the
   ``record_id`` / ``source_file`` it came from so conclusions stay
   evidence-based and never invented.

The output is ``cleaned_dataset.json`` with the same record schema as Phase 1,
plus a top-level ``anomaly_summary`` and ``investigation_leads`` block.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from typing import Any, Dict, Iterable, List, Optional, Tuple

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_URL_RE = re.compile(r"https?://[^\s\"'<>\\)]{4,200}", re.IGNORECASE)
_LOGON_RE = re.compile(r"\b(logon|logged on|4624|LogonType)\b", re.IGNORECASE)

# Directory-token hints for remote-access tooling (intrusion relevant).
_REMOTE_ACCESS = {"anydesk", "teamviewer", "screenconnect", "remoteutilities", "vnc"}

# Extensions that are suspicious when found inside a user profile.
_SUSPICIOUS_EXT = {
    "exe", "dll", "ps1", "bat", "cmd", "scr", "js", "vbs",
    "hta", "lnk", "docm", "dotm", "xlsm", "iso", "lnk",
}


def _iter_strings(value: Any) -> Iterable[str]:
    """Recursively yield every string contained in a JSON-like value."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for child in value.values():
            yield from _iter_strings(child)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _iter_strings(item)


def _file_size(original: Dict[str, Any]) -> Optional[float]:
    """Return the first file-size value found on a record, if numeric."""
    for key in ("Size", "FileSize", "file_size"):
        value = original.get(key)
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return float(value)
    return None


def _uploaded_size(original: Dict[str, Any]) -> Optional[float]:
    """Return the uploaded-size value on a record, if numeric."""
    value = original.get("uploaded_size")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    return None


def _fingerprint(data: Any) -> str:
    """Stable signature for an original payload (used for de-duplication)."""
    try:
        return json.dumps(data, sort_keys=True, default=str)
    except (TypeError, ValueError):
        return str(data)


def _record_anomaly_flags(record: Dict[str, Any]) -> List[str]:
    """Return the list of anomaly flags that apply to a single record."""
    flags: List[str] = []
    original = record.get("original_data", {}) or {}
    path = record.get("path", {}) or {}
    identifiers = record.get("identifiers", {}) or {}

    size = _file_size(original)
    uploaded = _uploaded_size(original)

    if size == 0:
        flags.append("zero_byte_file")
    if size is not None and uploaded is not None and uploaded < size:
        flags.append("incomplete_upload")
    if not record.get("timestamp"):
        flags.append("missing_timestamp")

    application = (path.get("application") or identifiers.get("application") or "").lower()
    if any(tool in application for tool in _REMOTE_ACCESS):
        flags.append("remote_access_tool")

    extension = (path.get("extension") or "").lower()
    username = path.get("username") or identifiers.get("username")
    if extension in _SUSPICIOUS_EXT and username:
        flags.append("suspicious_executable_in_user_profile")

    return flags


def _collect_leads(record: Dict[str, Any], leads: Dict[str, Any]) -> None:
    """Deep-scan one record for URLs / CVEs / logon hints and record them."""
    rid = record.get("record_id")
    source = record.get("source_file")
    original = record.get("original_data", {}) or {}

    for text in _iter_strings(original):
        for match in _URL_RE.findall(text):
            leads["urls"].setdefault(
                match, {"value": match, "source_file": source, "record_id": rid}
            )
        for match in _CVE_RE.findall(text):
            cve = match.upper()
            leads["cves"].setdefault(
                cve, {"value": cve, "source_file": source, "record_id": rid}
            )
        if _LOGON_RE.search(text) and len(leads["possible_logon_evidence"]) < 50:
            leads["possible_logon_evidence"].append(
                {"record_id": rid, "source_file": source,
                 "timestamp": record.get("timestamp")}
            )


def _incident_response_agent(records: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Extract the EDR/IR agent name + version (answers investigation Q1)."""
    for record in records:
        original = record.get("original_data", {}) or {}
        name = original.get("client_name")
        version = original.get("client_version")
        if name or version:
            return {
                "name": name,
                "version": version,
                "record_id": record.get("record_id"),
                "source_file": record.get("source_file"),
            }
    return None


def _deduplicate(
    records: List[Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], int]:
    """Drop exact duplicate payloads within the same source file."""
    seen: set = set()
    unique: List[Dict[str, Any]] = []
    removed = 0
    for record in records:
        signature = (record.get("source_file"), _fingerprint(record.get("original_data")))
        if signature in seen:
            removed += 1
            continue
        seen.add(signature)
        unique.append(record)
    return unique, removed


def analyze(dataset: Dict[str, Any]) -> Dict[str, Any]:
    """Clean the dataset and produce anomalies + investigation leads.

    Returns a dict ready to serialize as ``cleaned_dataset.json``.
    """
    records: List[Dict[str, Any]] = dataset.get("normalized_records", [])
    cleaned, duplicates_removed = _deduplicate(records)

    leads: Dict[str, Any] = {
        "urls": {},
        "cves": {},
        "possible_logon_evidence": [],
    }
    flag_counts: Counter = Counter()

    for record in cleaned:
        flags = _record_anomaly_flags(record)
        if flags:
            record["anomaly_flags"] = flags
            flag_counts.update(flags)
        _collect_leads(record, leads)

    anomaly_summary = {
        "input_records": len(records),
        "duplicate_records_removed": duplicates_removed,
        "cleaned_records": len(cleaned),
        "records_with_anomalies": sum(1 for r in cleaned if r.get("anomaly_flags")),
        "anomaly_flag_counts": dict(sorted(flag_counts.items())),
    }

    investigation_leads = {
        "incident_response_agent": _incident_response_agent(cleaned),
        "urls": sorted(leads["urls"].values(), key=lambda item: item["value"]),
        "cves": sorted(leads["cves"].values(), key=lambda item: item["value"]),
        "possible_logon_evidence": leads["possible_logon_evidence"],
    }

    return {
        "dataset_metadata": {
            **dataset.get("dataset_metadata", {}),
            "phase": "Phase 3 - Cleaning & Anomaly Detection",
        },
        "anomaly_summary": anomaly_summary,
        "investigation_leads": investigation_leads,
        "collection_problems": dataset.get("collection_problems", []),
        "normalized_records": cleaned,
    }
