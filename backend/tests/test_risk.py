from app.detection.risk import combined_confidence, risk_score, severity_band


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
