"""Process-wide detection state.

The Isolation Forest model is unsupervised and needs to be fit on a batch of
traffic before it can score anything. For this MVP the fitted model lives in
memory for the life of the process (see docs/architecture.md roadmap for
persisting it to disk). `scripts/load_dataset.py` fits it during ingestion;
until that happens, the API falls back to rule-only detection, which still
works on its own.
"""
from app.detection.ml import AnomalyDetector


class DetectionState:
    def __init__(self):
        self.anomaly_detector: AnomalyDetector | None = None

    def fit(self, feature_dicts: list[dict]):
        if not feature_dicts:
            return
        self.anomaly_detector = AnomalyDetector().fit(feature_dicts)


detection_state = DetectionState()
