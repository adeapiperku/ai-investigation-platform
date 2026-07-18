# python src/02_normalizers.py
"""Timestamp and path normalization helpers.

All timestamps are converted to UTC ISO-8601 strings ending in ``Z``.
Paths are decomposed into drive / directory / filename / extension plus best
effort username and application attribution.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Dict, Optional

# --------------------------------------------------------------------------- #
# Timestamp normalization
# --------------------------------------------------------------------------- #

# Magnitude thresholds used to guess the unit of an integer epoch value.
# Reference: 2025 in seconds is ~1.76e9.
_SECONDS_MAX = 1e11  # < ~year 5138 in seconds
_MILLIS_MAX = 1e14
_MICROS_MAX = 1e17
# anything larger is treated as nanoseconds.

# Regex for ISO-like and Velociraptor timestamps, e.g.
#   2025-08-03T18:14:01.8025178Z
#   2025-10-09 18:02:20.001254233 +0000 UTC
_ISO_RE = re.compile(
    r"^(?P<year>\d{4})-(?P<month>\d{2})-(?P<day>\d{2})"
    r"[ T]"
    r"(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})"
    r"(?:\.(?P<frac>\d+))?"
    r"\s*(?P<tz>Z|UTC|[+-]\d{2}:?\d{2})?"
    r"(?:\s*UTC)?$"
)

_NUMERIC_RE = re.compile(r"^-?\d+(?:\.\d+)?$")


def _epoch_to_iso(value: float) -> Optional[str]:
    """Convert a numeric epoch value to a UTC ISO-8601 string.

    The unit (s / ms / µs / ns) is inferred from the magnitude of ``value``.
    """
    magnitude = abs(value)
    if magnitude == 0:
        seconds = 0.0
    elif magnitude < _SECONDS_MAX:
        seconds = value
    elif magnitude < _MILLIS_MAX:
        seconds = value / 1_000
    elif magnitude < _MICROS_MAX:
        seconds = value / 1_000_000
    else:
        seconds = value / 1_000_000_000
    try:
        dt = datetime.fromtimestamp(seconds, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None
    return _format(dt)


def _parse_tz(token: Optional[str]) -> timezone:
    """Return a ``timezone`` for a parsed offset token (defaults to UTC)."""
    if not token or token in ("Z", "UTC"):
        return timezone.utc
    sign = 1 if token[0] == "+" else -1
    digits = token[1:].replace(":", "")
    hours, minutes = int(digits[:2]), int(digits[2:4])
    from datetime import timedelta

    return timezone(sign * timedelta(hours=hours, minutes=minutes))


def _iso_like_to_iso(text: str) -> Optional[str]:
    """Parse an ISO-8601 / Velociraptor timestamp string to canonical UTC."""
    match = _ISO_RE.match(text.strip())
    if not match:
        return None
    parts = match.groupdict()
    # Fractional seconds may have up to 9 digits; datetime supports 6 (micros).
    frac = (parts["frac"] or "")[:6].ljust(6, "0") if parts["frac"] else "0"
    try:
        dt = datetime(
            int(parts["year"]),
            int(parts["month"]),
            int(parts["day"]),
            int(parts["hour"]),
            int(parts["minute"]),
            int(parts["second"]),
            int(frac),
            tzinfo=_parse_tz(parts["tz"]),
        )
    except ValueError:
        return None
    return _format(dt.astimezone(timezone.utc))


def _format(dt: datetime) -> str:
    """Render a UTC datetime as ISO-8601 with a trailing ``Z``."""
    text = dt.astimezone(timezone.utc).isoformat()
    return text.replace("+00:00", "Z")


def normalize_timestamp(value: Any) -> Optional[str]:
    """Normalize any supported timestamp representation to UTC ISO-8601.

    Supports Unix seconds/milliseconds/microseconds/nanoseconds, ISO strings
    and Velociraptor ``YYYY-MM-DD HH:MM:SS.fffffffff +0000 UTC`` timestamps.
    Returns ``None`` when the value cannot be interpreted as a timestamp.
    """
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return _epoch_to_iso(float(value))
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        if _NUMERIC_RE.match(text):
            return _epoch_to_iso(float(text))
        return _iso_like_to_iso(text)
    return None


# --------------------------------------------------------------------------- #
# Path normalization
# --------------------------------------------------------------------------- #

_DRIVE_RE = re.compile(r"^[A-Za-z]:$")
_USER_RE = re.compile(r"[\\/]Users[\\/]([^\\/]+)", re.IGNORECASE)

# Best-effort mapping of directory tokens to application names.
_APP_HINTS = {
    "chrome": "Google Chrome",
    "google": "Google Chrome",
    "edge": "Microsoft Edge",
    "firefox": "Mozilla Firefox",
    "mozilla": "Mozilla Firefox",
    "outlook": "Microsoft Outlook",
    "onedrive": "OneDrive",
    "teams": "Microsoft Teams",
    "slack": "Slack",
    "anydesk": "AnyDesk",
    "teamviewer": "TeamViewer",
    "1password": "1Password",
    "webcache": "Windows WebCache",
    "powershell": "PowerShell",
}


def _clean_drive(raw: str) -> Optional[str]:
    """Extract a drive letter such as ``C:`` from a raw component."""
    token = raw.replace("\\\\.\\", "").strip("\\/")
    token = token.split("\\")[0].split("/")[0]
    return token if _DRIVE_RE.match(token) else None


def _guess_application(lowered_dirs: list[str], extension: str) -> Optional[str]:
    """Guess the owning application from directory tokens."""
    for token in lowered_dirs:
        for hint, app in _APP_HINTS.items():
            if hint in token:
                return app
    return None


def normalize_path(path_str: Any) -> Dict[str, Optional[str]]:
    """Decompose a Windows/UNIX path into normalized components.

    Returns a dict with ``drive``, ``directory``, ``filename``, ``extension``,
    ``username`` and ``application`` (any of which may be ``None``).
    """
    empty: Dict[str, Optional[str]] = {
        "drive": None,
        "directory": None,
        "filename": None,
        "extension": None,
        "username": None,
        "application": None,
        "full_path": None,
    }
    if not isinstance(path_str, str) or not path_str.strip():
        return empty

    original = path_str.strip()
    # Normalize the device prefix and split on either separator.
    working = original.replace("\\\\.\\", "").replace("\\", "/")
    segments = [seg for seg in working.split("/") if seg != ""]
    if not segments:
        return {**empty, "full_path": original}

    drive = _clean_drive(segments[0])
    body = segments[1:] if drive else segments

    filename = body[-1] if body else None
    directory_parts = body[:-1] if len(body) > 1 else []
    directory = "/".join(directory_parts) if directory_parts else None

    extension = None
    if filename and "." in filename.strip("."):
        extension = filename.rsplit(".", 1)[-1].lower()

    user_match = _USER_RE.search(original.replace("\\", "/"))
    username = user_match.group(1) if user_match else None

    lowered_dirs = [seg.lower() for seg in body]
    application = _guess_application(lowered_dirs, extension or "")

    return {
        "drive": drive,
        "directory": directory,
        "filename": filename,
        "extension": extension,
        "username": username,
        "application": application,
        "full_path": original,
    }
