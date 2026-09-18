"""Risk scoring: combines rule confidence and ML anomaly confidence into a
single 0-100 risk score and a severity band, using the weights in config.py.
"""
from app.config import settings


def combined_confidence(rule_confidence: float, ml_confidence: float, has_rule: bool, has_ml: bool) -> float:
    if has_rule and has_ml:
        return settings.RULE_WEIGHT * rule_confidence + settings.ML_WEIGHT * ml_confidence
    if has_rule:
        return rule_confidence
    if has_ml:
        return ml_confidence
    return 0.0


def risk_score(confidence: float) -> float:
    return round(confidence * 100, 1)


def severity_band(score: float) -> str:
    if score >= 85:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 35:
        return "MEDIUM"
    return "LOW"
