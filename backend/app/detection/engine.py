"""Detection engine: orchestrates rules + ML + MITRE mapping + risk scoring
for a single event's feature dict, producing an alert payload (or None).
"""
from dataclasses import dataclass

from app.detection import mitre, risk
from app.detection.ml import AnomalyDetector
from app.detection.rules import evaluate_rules


@dataclass
class DetectionResult:
    detection: str
    detection_source: str  # "rule" | "ml" | "rule+ml"
    mitre_technique: str | None
    mitre_technique_name: str | None
    confidence: float
    risk_score: float
    severity: str
    rationale: str


def evaluate_event(features: dict, anomaly_detector: AnomalyDetector | None = None) -> DetectionResult | None:
    rule_matches = evaluate_rules(features)
    top_rule = max(rule_matches, key=lambda m: m.confidence) if rule_matches else None

    is_anomaly, ml_confidence = (False, 0.0)
    if anomaly_detector is not None:
        is_anomaly, ml_confidence = anomaly_detector.score(features)

    has_rule = top_rule is not None
    has_ml = is_anomaly

    if not has_rule and not has_ml:
        return None

    if has_rule:
        detection_name = top_rule.detection
        rationale = top_rule.rationale
    else:
        detection_name = "Statistical traffic anomaly"
        rationale = f"Isolation Forest flagged this flow as an outlier (confidence={ml_confidence:.2f})"

    source = "rule+ml" if (has_rule and has_ml) else ("rule" if has_rule else "ml")

    confidence = risk.combined_confidence(
        rule_confidence=top_rule.confidence if has_rule else 0.0,
        ml_confidence=ml_confidence,
        has_rule=has_rule,
        has_ml=has_ml,
    )
    score = risk.risk_score(confidence)
    severity = risk.severity_band(score)
    technique, technique_name = mitre.lookup(detection_name)

    return DetectionResult(
        detection=detection_name,
        detection_source=source,
        mitre_technique=technique,
        mitre_technique_name=technique_name,
        confidence=round(confidence, 3),
        risk_score=score,
        severity=severity,
        rationale=rationale,
    )
