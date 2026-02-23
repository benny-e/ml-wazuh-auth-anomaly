from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, Optional

from dateutil import parser as dtparser

@dataclass
class AuthEvent:
    ts: str
    host: str
    user: str
    src_ip: str
    outcome: str  # "success" or "failure"
    program: str

def _get(d: Dict[str, Any], path: str, default=None):
    cur = d
    for p in path.split("."):
        if not isinstance(cur, dict) or p not in cur:
            return default
        cur = cur[p]
    return cur

def looks_like_auth(doc: Dict[str, Any]) -> bool:
    # Try common Wazuh groupings
    groups = _get(doc, "rule.groups", []) or []
    groups_str = " ".join(groups).lower()
    if any(k in groups_str for k in ["authentication", "sshd", "pam", "auth"]):
        return True

    # Fallback: check presence of typical fields
    if _get(doc, "data.dstuser") or _get(doc, "data.srcip"):
        msg = (_get(doc, "full_log") or _get(doc, "message") or "").lower()
        if "sshd" in msg or "authentication" in msg or "pam" in msg:
            return True

    return False

def parse_auth(doc: Dict[str, Any]) -> Optional[AuthEvent]:
    if not looks_like_auth(doc):
        return None

    ts = doc.get("@timestamp")
    if not ts:
        return None

    host = _get(doc, "agent.name") or _get(doc, "agent.hostname") or _get(doc, "host.name") or "unknown"

    # user field variants
    user = (
        _get(doc, "data.dstuser")
        or _get(doc, "data.user")
        or _get(doc, "data.username")
        or _get(doc, "user.name")
        or "unknown"
    )

    src_ip = (
        _get(doc, "data.srcip")
        or _get(doc, "source.ip")
        or _get(doc, "client.ip")
        or "unknown"
    )

    # outcome heuristics
    groups = _get(doc, "rule.groups", []) or []
    groups_l = " ".join(groups).lower()
    msg = (_get(doc, "full_log") or _get(doc, "message") or "").lower()

    outcome = "unknown"
    if any(k in groups_l for k in ["authentication_success", "success"]):
        outcome = "success"
    elif any(k in groups_l for k in ["authentication_failed", "failed", "failure"]):
        outcome = "failure"
    else:
        # fallback to message content
        if "failed password" in msg or "authentication failure" in msg:
            outcome = "failure"
        elif "accepted password" in msg or "accepted publickey" in msg:
            outcome = "success"

    program = _get(doc, "data.program") or _get(doc, "process.name") or "unknown"

    return AuthEvent(ts=ts, host=host, user=str(user), src_ip=str(src_ip), outcome=outcome, program=str(program))

def event_hour(ts: str) -> int:
    dt = dtparser.parse(ts)
    return int(dt.hour)

