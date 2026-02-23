from __future__ import annotations

from datetime import datetime, timezone

from mlwazuh.output.opensearch_writer import (
    daily_index,
    load_config,
    make_client,
    write_doc,
)

def main():
    os_cfg, out_cfg = load_config("config/default.yaml")
    client = make_client(os_cfg)

    doc = {
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "host": "ubuntu-lab-1",
        "event_family": "auth",
        "event_subtype": "login_success",
        "score": 0.91,
        "classification": "suspicious",
        "severity": 8,
        "reasons": ["New source IP", "Rare login hour (p=0.01)"],
        "entities": {"user": "bennett", "src_ip": "192.168.20.55", "process": None},
        "baseline": {
            "p_hour_user_host": 0.01,
            "p_srcip_user_host": 0.00,
            "is_new_srcip": True,
        },
        "source": {
            "wazuh_agent": "ubuntu-lab-1",
            "wazuh_rule_groups": ["authentication_success"],
        },
    }

    index_name = daily_index(out_cfg.index_prefix)
    write_doc(client, index_name, doc)

if __name__ == "__main__":
    main()
