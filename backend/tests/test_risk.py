from app.detection.risk import (
    apply_repeat_offender_boost,
    combined_confidence,
    repeat_offender_boost,
    risk_score,
    severity_band,
)


def test_combined_confidence_rule_only():
    assert combined_confidence(0.8, 0.0, has_rule=True, has_ml=False) == 0.8


def test_combined_confidence_ml_only():
    assert combined_confidence(0.0, 0.5, has_rule=False, has_ml=True) == 0.5


def test_combined_confidence_neither():
    assert combined_confidence(0.0, 0.0, has_rule=False, has_ml=False) == 0.0


def test_combined_confidence_weighted_blend():
    result = combined_confidence(1.0, 1.0, has_rule=True, has_ml=True)
    assert result == 1.0  # weights sum to 1.0 by default


def test_risk_score_scales_to_100():
    assert risk_score(1.0) == 100.0
    assert risk_score(0.0) == 0.0
    assert risk_score(0.5) == 50.0


def test_severity_bands():
    assert severity_band(90) == "CRITICAL"
    assert severity_band(70) == "HIGH"
    assert severity_band(40) == "MEDIUM"
    assert severity_band(10) == "LOW"
    assert severity_band(85) == "CRITICAL"
    assert severity_band(84.9) == "HIGH"


def test_repeat_offender_boost_is_zero_for_first_alert():
    assert repeat_offender_boost(0) == 0.0


def test_repeat_offender_boost_scales_then_caps():
    assert repeat_offender_boost(1) == 3.0
    assert repeat_offender_boost(2) == 6.0
    assert repeat_offender_boost(100) == 15.0  # capped, not unbounded


def test_apply_repeat_offender_boost_cannot_exceed_100():
    assert apply_repeat_offender_boost(95.0, prior_alert_count=10) == 100.0


def test_apply_repeat_offender_boost_no_prior_alerts_unchanged():
    assert apply_repeat_offender_boost(42.0, prior_alert_count=0) == 42.0
