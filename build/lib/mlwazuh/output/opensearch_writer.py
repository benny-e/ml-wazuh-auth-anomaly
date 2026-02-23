from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict

import yaml
from opensearchpy import OpenSearch

from mlwazuh.util.log import get_logger

log = get_logger(__name__)

@dataclass
class OpenSearchConfig:
    host: str
    port: int
    username: str
    password: str
    use_ssl: bool = True
    verify_certs: bool = False

@dataclass
class OutputConfig:
    index_prefix: str = "ml-anomalies"

def load_config(path: str) -> tuple[OpenSearchConfig, OutputConfig]:
    with open(path, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)

    os_cfg = cfg["opensearch"]
    out_cfg = cfg["output"]

    return (
        OpenSearchConfig(
            host=os_cfg["host"],
            port=int(os_cfg["port"]),
            username=os_cfg["username"],
            password=os_cfg["password"],
            use_ssl=bool(os_cfg.get("use_ssl", True)),
            verify_certs=bool(os_cfg.get("verify_certs", False)),
        ),
        OutputConfig(index_prefix=str(out_cfg.get("index_prefix", "ml-anomalies"))),
    )

def make_client(cfg: OpenSearchConfig) -> OpenSearch:
    client = OpenSearch(
        hosts=[{"host": cfg.host, "port": cfg.port}],
        http_auth=(cfg.username, cfg.password),
        use_ssl=cfg.use_ssl,
        verify_certs=cfg.verify_certs,
        ssl_show_warn=not cfg.verify_certs,
    )
    return client

def daily_index(prefix: str, dt: datetime | None = None) -> str:
    dt = dt or datetime.now(timezone.utc)
    return f"{prefix}-{dt:%Y.%m.%d}"

def write_doc(
    client: OpenSearch,
    index_name: str,
    doc: Dict[str, Any],
) -> Dict[str, Any]:
    resp = client.index(index=index_name, body=doc)
    log.info("Indexed doc to %s (result=%s)", index_name, resp.get("result"))
    return resp
