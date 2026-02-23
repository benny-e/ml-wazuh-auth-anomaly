from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Dict, Iterable, Tuple, List

from mlwazuh.parse.normalize_auth import AuthEvent, event_hour

Key = Tuple[str, str]  # (host, user)


@dataclass
class AuthBaseline:
    # Counts
    total_by_key: Dict[Key, int]
    hour_counts_by_key: Dict[Key, Counter]
    srcip_counts_by_key: Dict[Key, Counter]


def build_auth_baseline(events: Iterable[AuthEvent]) -> AuthBaseline:
    total_by_key: Dict[Key, int] = defaultdict(int)
    hour_counts_by_key: Dict[Key, Counter] = defaultdict(Counter)
    srcip_counts_by_key: Dict[Key, Counter] = defaultdict(Counter)

    for e in events:
        key = (e.host, e.user)
        total_by_key[key] += 1
        hour_counts_by_key[key][event_hour(e.ts)] += 1
        srcip_counts_by_key[key][e.src_ip] += 1

    return AuthBaseline(
        total_by_key=dict(total_by_key),
        hour_counts_by_key=dict(hour_counts_by_key),
        srcip_counts_by_key=dict(srcip_counts_by_key),
    )


def prob_hour(b: AuthBaseline, host: str, user: str, hour: int) -> float:
    key = (host, user)
    total = b.total_by_key.get(key, 0)
    if total <= 0:
        return 0.0
    # Laplace smoothing to avoid hard zeros for low volume
    return (b.hour_counts_by_key.get(key, Counter()).get(hour, 0) + 1) / (total + 24)


def prob_srcip(b: AuthBaseline, host: str, user: str, src_ip: str) -> float:
    key = (host, user)
    total = b.total_by_key.get(key, 0)
    if total <= 0:
        return 0.0
    # smoothing over "seen ips" is trickier; still useful
    return (b.srcip_counts_by_key.get(key, Counter()).get(src_ip, 0) + 1) / (total + 10)


# =============================================================================
# Isolation Forest helpers (minimal add-on)
# =============================================================================

FEATURE_ORDER_BASE = ["hour", "p_hour_user_host", "p_srcip_user_host", "is_failure"]
FEATURE_ORDER_WITH_NEW_SRCIP = FEATURE_ORDER_BASE + ["is_new_srcip"]


def is_known_srcip(b: AuthBaseline, host: str, user: str, src_ip: str) -> bool:
    """
    True if we've ever seen this src_ip for (host,user) in baseline.
    """
    key = (host, user)
    return b.srcip_counts_by_key.get(key, Counter()).get(src_ip, 0) > 0


def build_iforest_features(
    e: AuthEvent,
    baseline: AuthBaseline,
    include_is_new_srcip: bool = True,
) -> tuple[list[float], dict]:
    """
    Builds the numeric feature vector for an AuthEvent using your existing baseline.

    Feature vector:
      - hour (0..23)
      - p_hour_user_host (0..1)
      - p_srcip_user_host (0..1)
      - is_failure (0/1)
      - (optional) is_new_srcip (0/1)

    Returns: (x, derived) where derived is useful for reasons/baseline fields.
    """
    hour = event_hour(e.ts)
    p_hour = prob_hour(baseline, e.host, e.user, hour)
    p_srcip = prob_srcip(baseline, e.host, e.user, e.src_ip)

    # Your parse_auth sets e.outcome in ("success","failure")
    is_failure = 1.0 if e.outcome == "failure" else 0.0

    x = [float(hour), float(p_hour), float(p_srcip), float(is_failure)]

    is_new_srcip = 0.0
    if include_is_new_srcip:
        is_new_srcip = 0.0 if is_known_srcip(baseline, e.host, e.user, e.src_ip) else 1.0
        x.append(float(is_new_srcip))

    derived = {
        "hour": int(hour),
        "p_hour_user_host": float(p_hour),
        "p_srcip_user_host": float(p_srcip),
        "is_failure": float(is_failure),
        "is_new_srcip": float(is_new_srcip),
        "host": e.host,
        "user": e.user,
        "src_ip": e.src_ip,
        "outcome": e.outcome,
        "ts": e.ts,
    }
    return x, derived


def build_iforest_reasons(derived: dict) -> List[str]:
    """
    SOC-friendly reasons (not model internals; just actionable hints).
    """
    reasons: List[str] = []

    if derived.get("is_new_srcip", 0.0) >= 1.0:
        reasons.append("New/rare source IP for user+host")

    p_h = float(derived.get("p_hour_user_host", 0.0))
    if p_h < 0.05:
        reasons.append(f"Login at rare hour (p={p_h:.3f})")

    if derived.get("is_failure", 0.0) >= 1.0:
        reasons.append("Authentication failure")

    return reasons

