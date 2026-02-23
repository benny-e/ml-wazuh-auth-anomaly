from __future__ import annotations

from datetime import datetime, timezone
from typing import List
import argparse

import yaml
import numpy as np

from mlwazuh.ingest.wazuh_search import WazuhSearchConfig, search_recent
from mlwazuh.parse.normalize_auth import parse_auth
from mlwazuh.features.auth_baseline import build_iforest_features, build_iforest_reasons, AuthBaseline
from mlwazuh.models.iforest import load_bundle, score_iforest, ScoreNorm, severity_from_score, classify
from mlwazuh.output.opensearch_writer import make_client, daily_index, write_doc


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="data/models/auth_iforest.joblib")
    ap.add_argument("--lookback-minutes", type=int, default=None, help="defaults to config wazuh.lookback_minutes")
    ap.add_argument("--threshold", type=float, default=0.60)
    ap.add_argument("--out-prefix", default=None, help="defaults to config output.index_prefix")
    args = ap.parse_args()

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

    bundle = load_bundle(args.model)
    model = bundle["model"]
    baseline: AuthBaseline = bundle["baseline"]

    norm = ScoreNorm(
        lo_p5=float(bundle["score_norm"]["lo_p5"]),
        hi_p95=float(bundle["score_norm"]["hi_p95"]),
    )
    include_is_new_srcip = bool(bundle.get("include_is_new_srcip", True))

    lookback = int(args.lookback_minutes) if args.lookback_minutes is not None else int(wz_cfg["lookback_minutes"])
    recent_docs = search_recent(search_cfg, lookback_minutes=lookback, size=1000)

    # OpenSearch client (same as detect_auth.py)
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

    index_prefix = args.out_prefix or out_cfg.get("index_prefix", "ml-anomalies")
    index_name = daily_index(index_prefix)

    # Parse events
    recent_events: List = []
    recent_docs_kept = []  # keep doc to extract wazuh rule groups
    for d in recent_docs:
        e = parse_auth(d)
        if e and e.outcome in ("success", "failure"):
            recent_events.append(e)
            recent_docs_kept.append(d)

    if not recent_events:
        print("[OK] No auth events in lookback window")
        return

    # Feature matrix
    X = []
    derived_list = []
    for e in recent_events:
        x, derived = build_iforest_features(e, baseline, include_is_new_srcip=include_is_new_srcip)
        X.append(x)
        derived_list.append(derived)

    X = np.asarray(X, dtype=np.float32)

    # Scores (0..1)
    scores = score_iforest(model, norm, X)

    wrote = 0
    for e, d, derived, score in zip(recent_events, recent_docs_kept, derived_list, scores.tolist()):
        classification = classify(score, args.threshold)
        if classification != "suspicious":
            continue

        severity = severity_from_score(score)
        reasons = build_iforest_reasons(derived) or ["Anomalous authentication pattern"]

        # If failure AND suspicious, bump severity
        if e.outcome == "failure":
            severity = min(12, severity + 2)
            if "Authentication failure" not in reasons:
                reasons.append("Authentication failure")

        doc = {
            "@timestamp": e.ts,
            "host": e.host,
            "event_family": "auth",
            "event_subtype": f"login_{e.outcome}",
            "score": round(float(score), 4),
            "classification": classification,
            "severity": int(severity),
            "reasons": reasons,
            "entities": {"user": e.user, "src_ip": e.src_ip, "process": e.program},
            "baseline": {
                "p_hour_user_host": round(float(derived["p_hour_user_host"]), 4),
                 "p_srcip_user_host": round(float(derived["p_srcip_user_host"]), 4),
                 "is_new_srcip": bool(int(derived.get("is_new_srcip", 0.0))),
            },

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

