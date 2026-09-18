"""Risk scoring: combines rule confidence and ML anomaly confidence into a
single 0-100 risk score and a severity band, using the weights in config.py.

This is deliberately a modest, honestly-scoped model, not a claim of full
"cybersecurity risk" (which would also weigh asset criticality, internet
exposure, and threat intelligence -- none of which SentinelFlow has data
for). Two signals it *does* have and does incorporate: detection confidence
(rule + ML, blended) and how often the same source has already triggered
an alert (repeat_offender_boost). A device that has already fired several
alerts is more likely to represent an ongoing compromise than a first-time
detection at the same confidence level, so repeat activity nudges the score
up -- bounded, so it can't turn a low-confidence detection into a false
CRITICAL on repetition alone. See docs/architecture.md's roadmap for what a
fuller risk model (asset criticality, exposure, threat intel) would need.
"""
from app.config import settings

REPEAT_BOOST_PER_PRIOR_ALERT = 3.0
REPEAT_BOOST_CAP = 15.0


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


def repeat_offender_boost(prior_alert_count: int) -> float:
    """A small, capped score boost for a source that has already triggered
    other alerts. Not a substitute for real threat intelligence -- just
    the one piece of "has this host misbehaved before" evidence the app
    actually has on hand, applied conservatively."""
    if prior_alert_count <= 0:
        return 0.0
    return min(REPEAT_BOOST_CAP, prior_alert_count * REPEAT_BOOST_PER_PRIOR_ALERT)


def apply_repeat_offender_boost(score: float, prior_alert_count: int) -> float:
    return round(min(100.0, score + repeat_offender_boost(prior_alert_count)), 1)


def severity_band(score: float) -> str:
    if score >= 85:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 35:
        return "MEDIUM"
    return "LOW"
