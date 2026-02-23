from __future__ import annotations

from datetime import datetime, timezone, timedelta
from typing import List

import yaml

from mlwazuh.ingest.wazuh_search import WazuhSearchConfig, search_recent
from mlwazuh.parse.normalize_auth import parse_auth, event_hour
from mlwazuh.features.auth_baseline import build_auth_baseline, prob_hour, prob_srcip
from mlwazuh.output.opensearch_writer import load_config, make_client, daily_index, write_doc

def main():
    # Load YAML once
    cfg = yaml.safe_load(open("config/default.yaml", "r", encoding="utf-8"))

    os_cfg = cfg["opensearch"]
    wz_cfg = cfg["wazuh"]
    out_cfg = cfg["output"]

    # Search configs
    search_cfg = WazuhSearchConfig(
        base_url=f"https://{os_cfg['host']}:{os_cfg['port']}",
        username=os_cfg["username"],
        password=os_cfg["password"],
        index_pattern=wz_cfg["index_pattern"],
        verify_certs=bool(os_cfg.get("verify_certs", False)),
    )

    # 1) Build baseline from last N days (start with 14)
    baseline_days = int(wz_cfg.get("baseline_days", 14))
    baseline_minutes = baseline_days * 24 * 60

    baseline_docs = search_recent(search_cfg, lookback_minutes=baseline_minutes, size=5000)
    baseline_events: List = []
    for d in baseline_docs:
        e = parse_auth(d)
        if e and e.outcome in ("success", "failure"):
            baseline_events.append(e)

    baseline = build_auth_baseline(baseline_events)

    # 2) Pull recent docs to score
    lookback = int(wz_cfg["lookback_minutes"])
    recent_docs = search_recent(search_cfg, lookback_minutes=lookback, size=1000)

    # 3) Index anomalies
    client = make_client(
        type("Tmp", (), {
            "host": os_cfg["host"],
            "port": int(os_cfg["port"]),
            "username": os_cfg["username"],
            "password": os_cfg["password"],
            "use_ssl": bool(os_cfg.get("use_ssl", True)),
            "verify_certs": bool(os_cfg.get("verify_certs", False)),
        })()
    )

    index_name = daily_index(out_cfg.get("index_prefix", "ml-anomalies"))

    wrote = 0
    for d in recent_docs:
        e = parse_auth(d)
        if not e or e.outcome not in ("success", "failure"):
            continue

        hr = event_hour(e.ts)
        p_h = prob_hour(baseline, e.host, e.user, hr)
        p_ip = prob_srcip(baseline, e.host, e.user, e.src_ip)

        # Interpretable scoring:
        # Lower probabilities = more anomalous
        # Score is 0..1-ish (not perfect but stable)
        rarity = (1.0 - p_h) * 0.5 + (1.0 - p_ip) * 0.5

        reasons = []
        if p_ip < 0.05:
            reasons.append("New/rare source IP for user+host")
        if p_h < 0.05:
            reasons.append(f"Login at rare hour (p={p_h:.3f})")

        severity = 3
        classification = "normal"

        if rarity >= 0.75:
            classification = "suspicious"
            severity = 7
        if rarity >= 0.90:
            severity = 10

        if e.outcome == "failure" and classification == "suspicious":
            severity = min(12, severity + 2)
            reasons.append("Authentication failure with anomalous context")

        if classification != "suspicious":
            continue

        doc = {
            "@timestamp": e.ts,
            "host": e.host,
            "event_family": "auth",
            "event_subtype": f"login_{e.outcome}",
            "score": round(float(rarity), 4),
            "classification": classification,
            "severity": int(severity),
            "reasons": reasons or ["Anomalous authentication pattern"],
            "entities": {"user": e.user, "src_ip": e.src_ip, "process": e.program},
            "baseline": {"p_hour_user_host": round(p_h, 4), "p_srcip_user_host": round(p_ip, 4)},
            "source": {
                "wazuh_agent": e.host,
                "wazuh_rule_groups": (d.get("rule", {}) or {}).get("groups", []),
            },
        }

        write_doc(client, index_name, doc)
        wrote += 1

    print(f"Wrote {wrote} suspicious auth anomalies to {index_name}")

if __name__ == "__main__":
    main()

