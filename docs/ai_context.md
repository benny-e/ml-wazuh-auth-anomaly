# AI Context – Wazuh ML Anomaly Detection Project

## Project Goal
Build an external, Python-based ML anomaly detection service that:
- consumes Wazuh logs (auth, process, network)
- establishes a baseline of normal behavior
- detects anomalies (rare commands, odd login times, spikes in failures)
- outputs scores to Grafana

## Environment
- Single-user SOC-style homelab
- Low log volume
- No labeled attack data
- Wazuh already deployed and ingesting logs

## Constraints
- ML service is external to Wazuh
- Results visualized in Grafana
- Emphasis on realism over scale

## AI Usage Rules
- Prefer explainability over “black box” ML
- Favor isolation forest / statistical baselines
- Treat this like a SOC detection pipeline, not a Kaggle project

