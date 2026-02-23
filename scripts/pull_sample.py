from __future__ import annotations

import yaml
from pprint import pprint

from mlwazuh.ingest.wazuh_search import WazuhSearchConfig, search_recent

def main():
    cfg = yaml.safe_load(open("config/default.yaml", "r", encoding="utf-8"))

    os_cfg = cfg["opensearch"]
    wz_cfg = cfg["wazuh"]

    search_cfg = WazuhSearchConfig(
        base_url=f"https://{os_cfg['host']}:{os_cfg['port']}",
        username=os_cfg["username"],
        password=os_cfg["password"],
        index_pattern=wz_cfg["index_pattern"],
        verify_certs=bool(os_cfg.get("verify_certs", False)),
    )

    docs = search_recent(search_cfg, lookback_minutes=int(wz_cfg["lookback_minutes"]), size=10)

    print("\n--- Showing 2 most recent docs (_source) ---\n")
    for d in docs[:2]:
        pprint(d)

if __name__ == "__main__":
    main()
