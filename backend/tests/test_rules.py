from app.detection.rules import evaluate_rules


def base_features(**overrides):
    features = {
        "duration": 0, "protocol_type": "tcp", "service": "http", "flag": "SF",
        "src_bytes": 100, "dst_bytes": 100, "land": 0, "wrong_fragment": 0,
        "urgent": 0, "hot": 0, "num_failed_logins": 0, "logged_in": 1,
        "num_compromised": 0, "root_shell": 0, "su_attempted": 0, "num_root": 0,
        "num_file_creations": 0, "num_shells": 0, "num_access_files": 0,
        "count": 1, "srv_count": 1, "serror_rate": 0.0, "srv_serror_rate": 0.0,
        "rerror_rate": 0.0, "srv_rerror_rate": 0.0, "same_srv_rate": 1.0,
        "diff_srv_rate": 0.0, "srv_diff_host_rate": 0.0,
    }
    features.update(overrides)
    return features


def test_benign_traffic_triggers_no_rule():
    matches = evaluate_rules(base_features())
    assert matches == []


def test_land_attack_detected():
    matches = evaluate_rules(base_features(land=1))
    detections = [m.detection for m in matches]
    assert "Land attack (spoofed src=dst)" in detections


def test_credential_guessing_detected_on_repeated_failed_logins():
    matches = evaluate_rules(base_features(num_failed_logins=5))
    detections = [m.detection for m in matches]
    assert "Credential guessing (SNMP/FTP/service auth)" in detections


def test_brute_force_detected_on_single_failed_login_with_volume():
    matches = evaluate_rules(base_features(num_failed_logins=1, logged_in=0, count=10))
    detections = [m.detection for m in matches]
    assert "SSH/Telnet brute-force behaviour" in detections


def test_port_scan_detected_on_rejected_zero_byte_connection():
    matches = evaluate_rules(base_features(flag="REJ", src_bytes=0, dst_bytes=0, count=1))
    detections = [m.detection for m in matches]
    assert "Port scanning" in detections


def test_port_scan_not_triggered_when_payload_present():
    matches = evaluate_rules(base_features(flag="REJ", src_bytes=50, dst_bytes=0, count=10))
    detections = [m.detection for m in matches]
    assert "Port scanning" not in detections


def test_dos_pattern_detected_on_high_serror_rate():
    matches = evaluate_rules(base_features(serror_rate=0.9, count=100))
    detections = [m.detection for m in matches]
    assert "Network denial-of-service pattern" in detections


def test_privilege_escalation_detected_on_root_shell():
    matches = evaluate_rules(base_features(root_shell=1))
    detections = [m.detection for m in matches]
    assert "Privilege escalation indicators" in detections


def test_suspicious_command_execution_on_shell_activity():
    matches = evaluate_rules(base_features(num_shells=1))
    detections = [m.detection for m in matches]
    assert "Suspicious remote command execution" in detections


def test_suspicious_command_execution_on_hot_indicators():
    matches = evaluate_rules(base_features(hot=3))
    detections = [m.detection for m in matches]
    assert "Suspicious remote command execution" in detections


def test_unusual_outbound_volume_detected():
    matches = evaluate_rules(base_features(src_bytes=100, dst_bytes=1_000_000))
    detections = [m.detection for m in matches]
    assert "Unusual outbound data volume" in detections


def test_multiple_rules_can_fire_together():
    matches = evaluate_rules(base_features(land=1, root_shell=1))
    detections = {m.detection for m in matches}
    assert {"Land attack (spoofed src=dst)", "Privilege escalation indicators"} <= detections
