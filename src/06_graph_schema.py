"""Vocabulary for the investigation knowledge graph.

Centralizes entity types, relationship types and the node-id scheme so the
builder and later phases share one definition.
"""

from __future__ import annotations

import re
from typing import Optional

# --------------------------------------------------------------------------- #
# Entity (node) types
# --------------------------------------------------------------------------- #
CLIENT = "client"        # Velociraptor agent / endpoint identity (C.xxxx)
HOST = "host"            # machine hostname / fqdn
SESSION = "session"      # collection flow / session (F.xxxx)
REQUEST = "request"      # a request inside a flow
USER = "user"            # a user account found on the host
APPLICATION = "application"
FILE = "file"
HASH = "hash"
IP = "ip"
MAC = "mac"
ARTIFACT = "artifact"    # Velociraptor artifact that produced evidence

# --------------------------------------------------------------------------- #
# Relationship (edge) types
# --------------------------------------------------------------------------- #
IS_HOST = "IS_HOST"                  # client -> host
HAS_IP = "HAS_IP"                    # client -> ip
HAS_MAC = "HAS_MAC"                  # client -> mac
RAN = "RAN"                          # client -> session
HAS_REQUEST = "HAS_REQUEST"          # session -> request
COLLECTED_ARTIFACT = "COLLECTED_ARTIFACT"  # session -> artifact
PRODUCED_BY = "PRODUCED_BY"          # file -> artifact
HAS_USER = "HAS_USER"                # host -> user
OWNS = "OWNS"                        # user -> file
HAS_HASH = "HAS_HASH"                # file -> hash
ASSOCIATED_WITH = "ASSOCIATED_WITH"  # file -> application
USED = "USED"                        # user -> application
COLLECTED = "COLLECTED"              # session -> file

_ID_SAFE = re.compile(r"\s+")


def _slug(value: str) -> str:
    """Normalize a value into a compact, comparable id fragment."""
    return _ID_SAFE.sub(" ", value.strip()).lower()


def node_id(node_type: str, value: str) -> str:
    """Build a stable node id from a type and a raw identifier value.

    Case-sensitive forensic identifiers (client/session/request) keep their
    original casing; descriptive entities are lower-cased for de-duplication.
    """
    if node_type in (CLIENT, SESSION, REQUEST, ARTIFACT):
        key = value.strip()
    elif node_type == FILE:
        key = value.strip().replace("\\", "/").lower()
    else:
        key = _slug(value)
    return f"{node_type}:{key}"


def is_valid(value: Optional[str]) -> bool:
    """Return whether a raw identifier value is usable as a node."""
    return isinstance(value, str) and value.strip() != ""
