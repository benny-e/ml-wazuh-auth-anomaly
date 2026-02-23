from __future__ import annotations

from datetime import datetime, timezone
from typing import List
import os
import argparse

import yaml
import numpy as np

from mlwazuh.ingest.wazuh_search import WazuhSearchConfig, search_recent
from mlwazuh.parse.normalize_auth import parse_auth
from mlwazuh.features.auth_baseline import build_auth_baseline, build_iforest_features
from mlwazuh.models.iforest import train_iforest, save_bundle


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--days", type=int, default=14)
    ap.add_argument("--contamination", type=float, default=0.02)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--include-is-new-srcip", action="store_true")
    ap.add_argument("--model-out", default="data/models/auth_iforest.joblib")
    args = ap.parse_args()

    os.makedirs(os.path.dirname(args.model_out), exist_ok=True)

    # Load YAML once
    cfg = yaml.safe_load(open("config/default.yaml", "r", encoding="utf-8"))
    os_cfg = cfg["opensearch"]
    wz_cfg = cfg["wazuh"]

    # Search configs (same as detect_auth.py)
    search_cfg = WazuhSearchConfig(
        base_url=f"https://{os_cfg['host']}:{os_cfg['port']}",
        username=os_cfg["username"],
        password=os_cfg["password"],
        index_pattern=wz_cfg["index_pattern"],
        verify_certs=bool(os_cfg.get("verify_certs", False)),
    )

    baseline_minutes = int(args.days) * 24 * 60
    baseline_docs = search_recent(search_cfg, lookback_minutes=baseline_minutes, size=5000)

    baseline_events: List = []
    for d in baseline_docs:
        e = parse_auth(d)
        if e and e.outcome in ("success", "failure"):
            baseline_events.append(e)

    if len(baseline_events) < 30:
        raise SystemExit(f"Not enough baseline auth events ({len(baseline_events)}). Need ~30+.")

    baseline = build_auth_baseline(baseline_events)

    X = []
    for e in baseline_events:
        x, _ = build_iforest_features(e, baseline, include_is_new_srcip=args.include_is_new_srcip)
        X.append(x)

    X = np.asarray(X, dtype=np.float32)

    model, norm = train_iforest(X, contamination=args.contamination, seed=args.seed)

    bundle = {
        "model": model,
        "score_norm": {"lo_p5": norm.lo_p5, "hi_p95": norm.hi_p95},
        "trained_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "baseline_days": int(args.days),
        "contamination": float(args.contamination),
        "include_is_new_srcip": bool(args.include_is_new_srcip),
        "baseline": baseline,
        "n_train": int(X.shape[0]),
    }

    save_bundle(args.model_out, bundle)
    print(f"[OK] Trained IF on {X.shape[0]} baseline auth events")
    print(f"[OK] Saved model -> {args.model_out}")
    print(f"[OK] Score anchors p5={norm.lo_p5:.6f} p95={norm.hi_p95:.6f}")


if __name__ == "__main__":
    main()

