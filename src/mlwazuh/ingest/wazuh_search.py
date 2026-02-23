from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

import requests

from mlwazuh.util.log import get_logger

log = get_logger(__name__)

@dataclass
class WazuhSearchConfig:
    base_url: str             
    username: str
    password: str
    index_pattern: str = "wazuh-alerts-*"
    verify_certs: bool = False

def build_time_range(lookback_minutes: int) -> Dict[str, Any]:
    now = datetime.now(timezone.utc)
    start = now - timedelta(minutes=lookback_minutes)
    return {
        "range": {
            "@timestamp": {
                "gte": start.isoformat(),
                "lte": now.isoformat(),
            }
        }
    }

def search_recent(
    cfg: WazuhSearchConfig,
    lookback_minutes: int = 60,
    size: int = 200,
) -> List[Dict[str, Any]]:
    """
    Pull recent Wazuh alert docs from the indexer.
    Returns list of _source dicts.
    """
    url = f"{cfg.base_url.rstrip('/')}/{cfg.index_pattern}/_search"
    query = {
        "size": size,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "_source": True,
        "query": {"bool": {"filter": [build_time_range(lookback_minutes)]}},
    }

    r = requests.get(
        url,
        auth=(cfg.username, cfg.password),
        json=query,
        verify=cfg.verify_certs,
        timeout=20,
    )
    r.raise_for_status()
    data = r.json()

    hits = data.get("hits", {}).get("hits", [])
    sources = [h.get("_source", {}) for h in hits if "_source" in h]

    log.info("Pulled %d docs from %s", len(sources), cfg.index_pattern)
    return sources
