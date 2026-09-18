from app.detection.engine import evaluate_event


def test_no_detection_for_benign_flow():
    result = evaluate_event({"flag": "SF", "src_bytes": 100, "dst_bytes": 100, "count": 1})
    assert result is None


def test_rule_only_detection_maps_to_mitre():
    result = evaluate_event({"land": 1})
    assert result is not None
    assert result.detection_source == "rule"
    assert result.mitre_technique == "T1498"
    assert result.severity in {"HIGH", "CRITICAL"}


def test_severity_scales_with_confidence():
    weak = evaluate_event({"num_failed_logins": 1, "logged_in": 0, "count": 10})
    strong = evaluate_event({"root_shell": 1})
    assert weak is not None and strong is not None
    assert strong.risk_score >= weak.risk_score
