# ml-wazuh-auth-anomaly

Isolation Forest anomaly detection for Wazuh authentication alerts stored in OpenSearch.

This project pulls authentication alerts from OpenSearch, builds a behavioral baseline using Isolation Forest, and flags anomalous login activity.

---

## Features

- Pulls auth alerts from OpenSearch
- Extracts baseline authentication features
- Trains an Isolation Forest model
- Detects suspicious login behavior
- Optional writing of results back to OpenSearch

---

## Requirements

- Python 3.10+
- Wazuh
- OpenSearch

---

## Setup

Clone the repository and create a virtual environment:

python -m venv .venv
source .venv/bin/activate
pip install -e .

Copy the example configuration:

cp config/default.yaml.example config/default.yaml

Edit `config/default.yaml` and insert your OpenSearch credentials and index pattern.

---

## Train the Model

PYTHONPATH=src python scripts/train_auth_iforest.py

This will:
- Pull recent authentication alerts
- Build feature vectors
- Train an Isolation Forest model
- Save the model locally in `data/models/`

---

## Detect Anomalies

PYTHONPATH=src python scripts/detect_auth_iforest.py

This will:
- Pull recent authentication alerts
- Score events using the trained model
- Flag suspicious activity

---

## Configuration

`config/default.yaml` contains:

- OpenSearch connection details
- Index pattern (default: `wazuh-alerts-*`)
- SSL verification settings

This file is intentionally ignored by git because it contains credentials.

---

## Project Structure

config/        # Configuration files  
scripts/       # CLI entry points  
src/mlwazuh/   # Core package (features, models, ingest, output)  
data/          # Local model artifacts (ignored by git)

---

## Notes

- `config/default.yaml` is ignored (contains credentials)
- Model artifacts are stored locally and not committed
- Default lookback window is defined in training/detection scripts

---


