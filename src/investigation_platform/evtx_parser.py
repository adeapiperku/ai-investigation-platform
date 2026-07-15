"""Parse Windows Security.evtx for logon events (Event ID 4624).

Only used to answer questions the file-metadata pipeline can't: exact
logon timestamps for real user accounts. Every returned event still
carries its EventRecordID so it can be pointed at directly in the
Security.evtx file - this is not a summary, it's the raw event fields.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Optional

from Evtx.Evtx import Evtx

# Windows/system accounts that show up constantly and aren't real people.
NON_HUMAN_ACCOUNTS = {
    "system", "local service", "network service", "-", "dwm-1", "dwm-2",
    "umfd-0", "umfd-1", "umfd-2",
}


def resolve_upload_path(case_root: Path, windows_path: str) -> Path:
    """Map a raw Windows path (e.g. C:\\Windows\\...\\Security.evtx) to
    where Velociraptor actually stored the collected copy under uploads/."""
    p = windows_path.replace("\\\\.\\", "")
    parts = p.split("\\")
    drive = parts[0].replace(":", "%3A")
    return Path(case_root) / "uploads" / "auto" / drive / Path(*parts[1:])


_FIELD_RE = re.compile(r'<Data Name="([^"]+)">([^<]*)</Data>')
_TIME_RE = re.compile(r'<TimeCreated SystemTime="([^"]+)"')
_RECORD_ID_RE = re.compile(r"<EventRecordID>(\d+)</EventRecordID>")


def parse_logon_events(evtx_path: Path, username: Optional[str] = None) -> list[dict[str, Any]]:
    """Extract 4624 (successful logon) events, optionally filtered to a
    given TargetUserName (case-insensitive), excluding system/service
    accounts when no username filter is given."""
    events: list[dict[str, Any]] = []
    with Evtx(str(evtx_path)) as evtx:
        for record in evtx.records():
            xml = record.xml()
            if "<EventID" not in xml or ">4624<" not in xml.split("<EventID", 1)[1][:30]:
                continue

            fields = dict(_FIELD_RE.findall(xml))
            target_user = fields.get("TargetUserName", "")
            if username is not None:
                if target_user.lower() != username.lower():
                    continue
            elif target_user.lower() in NON_HUMAN_ACCOUNTS or target_user.endswith("$"):
                continue

            time_match = _TIME_RE.search(xml)
            record_id_match = _RECORD_ID_RE.search(xml)
            events.append(
                {
                    "time_utc": time_match.group(1) if time_match else None,
                    "event_record_id": record_id_match.group(1) if record_id_match else None,
                    "target_user_name": target_user,
                    "target_domain_name": fields.get("TargetDomainName"),
                    "logon_type": fields.get("LogonType"),
                    "workstation_name": fields.get("WorkstationName"),
                    "ip_address": fields.get("IpAddress"),
                }
            )
    return events


if __name__ == "__main__":
    import json
    import sys

    case_root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(
        "TriDsk-WKS02-C.1dfcd21bd3d01cc0-F.D3JVHAK4B16NM"
    )
    username = sys.argv[2] if len(sys.argv) > 2 else None

    evtx_path = resolve_upload_path(case_root, r"C:\Windows\System32\winevt\Logs\Security.evtx")
    events = parse_logon_events(evtx_path, username)
    print(json.dumps(events, indent=2))
    print(f"\n{len(events)} matching logon events found", file=sys.stderr)
