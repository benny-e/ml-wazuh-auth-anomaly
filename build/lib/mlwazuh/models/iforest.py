# src/mlwazuh/models/iforest.py
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Literal, Mapping, Optional, TypedDict, Union, cast

import numpy as np
from joblib import dump, load
from sklearn.ensemble import IsolationForest


# Public types
ClassLabel = Literal["normal", "suspicious"]


@dataclass(frozen=True)
class ScoreNorm:
    """
    Robust score normalization anchors for mapping raw anomaly-ness to [0, 1].

    We compute raw anomaly-ness as -decision_function(X) so that:
      - larger raw values => more anomalous
    Then we anchor:
      - lo_p5 = 5th percentile of raw on training data
      - hi_p95 = 95th percentile of raw on training data

    Normalized score:
      score = clip((raw - lo_p5) / (hi_p95 - lo_p5), 0, 1)
    """
    lo_p5: float
    hi_p95: float


class IForestBundle(TypedDict, total=False):
    """
    Recommended on-disk bundle schema (joblib).

    Keep it flexible (total=False) so you can add fields without breaking loads.
    """
    model: IsolationForest
    norm: ScoreNorm
    threshold: float
    family: str
    feature_names: list[str]
    contamination: float
    seed: int
    trained_at: str  # ISO timestamp
    version: str
    meta: Dict[str, Any]


def _normalize(raw_anom: np.ndarray, norm: ScoreNorm) -> np.ndarray:
    """
    Map raw anomaly-ness values to [0, 1] using robust percentile anchors.
    """
    denom = (norm.hi_p95 - norm.lo_p5) if (norm.hi_p95 > norm.lo_p5) else 1e-6
    s = (raw_anom - norm.lo_p5) / denom
    return np.clip(s, 0.0, 1.0)


def _raw_anom_from_model(model: IsolationForest, X: np.ndarray) -> np.ndarray:
    """
    Compute raw anomaly-ness = -decision_function(X).
    decision_function: higher => more normal; we invert so higher => more anomalous.
    """
    df = model.decision_function(X)
    return (-df).astype(np.float32)


def train_iforest(
    X: np.ndarray,
    contamination: float = 0.02,
    seed: int = 42,
    *,
    n_estimators: int = 200,
    max_samples: Union[int, float, str] = "auto",
    n_jobs: int = -1,
) -> tuple[IsolationForest, ScoreNorm]:
    """
    Train an IsolationForest model and compute ScoreNorm anchors from training data.

    Returns:
      (model, norm)

    Score semantics:
      - score is in [0, 1]
      - higher score means "more anomalous"
    """
    if X is None:
        raise ValueError("X must not be None")
    if not isinstance(X, np.ndarray):
        raise TypeError(f"X must be a numpy.ndarray, got {type(X)!r}")
    if X.ndim != 2:
        raise ValueError(f"X must be 2D array (n_samples, n_features), got shape={X.shape!r}")
    if X.shape[0] < 2:
        raise ValueError(f"Need at least 2 samples to train, got n_samples={X.shape[0]}")

    model = IsolationForest(
        n_estimators=n_estimators,
        max_samples=max_samples,
        contamination=contamination,
        random_state=seed,
        n_jobs=n_jobs,
    )
    model.fit(X)

    raw = _raw_anom_from_model(model, X)

    lo = float(np.percentile(raw, 5))
    hi = float(np.percentile(raw, 95))
    if hi <= lo:
        hi = lo + 1e-6

    return model, ScoreNorm(lo_p5=lo, hi_p95=hi)


def score_iforest(model: IsolationForest, norm: ScoreNorm, X: np.ndarray) -> np.ndarray:
    """
    Score samples with a trained IsolationForest model.

    Returns:
      numpy array of scores in [0, 1], higher = more anomalous.
    """
    if X is None:
        raise ValueError("X must not be None")
    if not isinstance(X, np.ndarray):
        raise TypeError(f"X must be a numpy.ndarray, got {type(X)!r}")
    if X.ndim != 2:
        raise ValueError(f"X must be 2D array (n_samples, n_features), got shape={X.shape!r}")

    raw = _raw_anom_from_model(model, X)
    return _normalize(raw, norm)


def save_bundle(path: str, bundle: Mapping[str, Any]) -> None:
    """
    Persist a model bundle to disk (joblib).
    """
    dump(dict(bundle), path)


def load_bundle(path: str) -> Dict[str, Any]:
    """
    Load a model bundle from disk (joblib).
    """
    return cast(Dict[str, Any], load(path))


def classify(score: float, threshold: float) -> ClassLabel:
    """
    Classify a normalized anomaly score using a stored threshold.
    """
    return "suspicious" if float(score) >= float(threshold) else "normal"


def severity_from_score(score: float) -> int:
    """
    Convert a normalized score in [0, 1] to an integer severity level.

    Always returns an int in [0, 10] (consistent typing).
    You can map this to whatever your downstream expects (e.g., Wazuh rule level).
    """
    s = float(score)
    if s >= 0.90:
        return 10
    if s >= 0.75:
        return 7
    if s >= 0.55:
        return 5
    if s >= 0.35:
        return 4
    return 0


def severity_label(level: int) -> str:
    """
    Optional helper: convert a severity int into a label.
    """
    lvl = int(level)
    if lvl >= 10:
        return "critical"
    if lvl >= 7:
        return "high"
    if lvl >= 5:
        return "medium"
    if lvl >= 4:
        return "low"
    return "info"


def validate_bundle(bundle: Mapping[str, Any]) -> None:
    """
    Optional: sanity-check a loaded bundle. Call this in scripts if you want.
    """
    if "model" not in bundle:
        raise KeyError("bundle missing 'model'")
    if "norm" not in bundle:
        raise KeyError("bundle missing 'norm'")
    if "threshold" not in bundle:
        raise KeyError("bundle missing 'threshold'")

    model = bundle["model"]
    norm = bundle["norm"]
    threshold = bundle["threshold"]

    if not isinstance(model, IsolationForest):
        raise TypeError(f"bundle['model'] must be IsolationForest, got {type(model)!r}")
    if not isinstance(norm, ScoreNorm):
        raise TypeError(f"bundle['norm'] must be ScoreNorm, got {type(norm)!r}")

    t = float(threshold)
    if not (0.0 <= t <= 1.0):
        raise ValueError(f"bundle['threshold'] must be in [0, 1], got {t}")
