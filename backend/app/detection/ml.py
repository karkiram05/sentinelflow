"""Statistical anomaly detection using Isolation Forest.

This model is unsupervised and never sees ground-truth labels: it is fit on
the numeric feature vectors of a batch of traffic and flags points that sit
far from the bulk of the distribution. This exists specifically to catch
things the hand-written rules in rules.py don't have an explicit threshold
for.
"""
from __future__ import annotations

import numpy as np
from sklearn.ensemble import IsolationForest

from app.config import settings
from app.detection.features import numeric_vector


class AnomalyDetector:
    def __init__(self, contamination: float | None = None, random_state: int | None = None):
        self.contamination = contamination or settings.ML_CONTAMINATION
        self.random_state = random_state if random_state is not None else settings.ML_RANDOM_STATE
        self.model = IsolationForest(
            n_estimators=200,
            contamination=self.contamination,
            random_state=self.random_state,
        )
        self._fitted = False

    def fit(self, feature_dicts: list[dict]) -> "AnomalyDetector":
        X = np.array([numeric_vector(f) for f in feature_dicts])
        self.model.fit(X)
        self._fitted = True
        return self

    def score(self, features: dict) -> tuple[bool, float]:
        """Return (is_anomaly, confidence in [0, 1])."""
        if not self._fitted:
            raise RuntimeError("AnomalyDetector.fit() must be called before score()")
        X = np.array([numeric_vector(features)])
        prediction = self.model.predict(X)[0]  # -1 anomaly, 1 normal
        raw_score = self.model.score_samples(X)[0]  # higher = more normal

        # score_samples is roughly in [-0.5, 0.5]; convert to a 0..1
        # "anomaly confidence" where more negative raw_score -> higher confidence.
        confidence = float(np.clip(0.5 - raw_score, 0.0, 1.0))
        is_anomaly = bool(prediction == -1)
        return is_anomaly, confidence

    def score_batch(self, feature_dicts: list[dict]) -> list[tuple[bool, float]]:
        return [self.score(f) for f in feature_dicts]
