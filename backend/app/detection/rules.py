"""Rule-based detectors.

Each rule looks at the flow-level feature dict produced by
`app.detection.features.extract_features` and returns a `RuleMatch` when it
fires. Rules are intentionally simple, explainable thresholds — the kind a
SOC analyst could read and audit — rather than a black box. The Isolation
Forest model in `ml.py` covers what these rules miss.
"""
from dataclasses import dataclass


@dataclass
class RuleMatch:
    detection: str
    confidence: float  # 0..1
    rationale: str


def _get(features: dict, key: str, default=0):
    value = features.get(key, default)
    return value if value is not None else default


def evaluate_rules(features: dict) -> list[RuleMatch]:
    matches: list[RuleMatch] = []

    land = _get(features, "land", 0)
    num_failed_logins = _get(features, "num_failed_logins", 0)
    logged_in = _get(features, "logged_in", 0)
    count = _get(features, "count", 0)
    srv_count = _get(features, "srv_count", 0)
    flag = str(_get(features, "flag", ""))
    src_bytes = _get(features, "src_bytes", 0)
    dst_bytes = _get(features, "dst_bytes", 0)
    serror_rate = _get(features, "serror_rate", 0.0)
    same_srv_rate = _get(features, "same_srv_rate", 0.0)
    root_shell = _get(features, "root_shell", 0)
    num_root = _get(features, "num_root", 0)
    su_attempted = _get(features, "su_attempted", 0)
    num_shells = _get(features, "num_shells", 0)
    num_file_creations = _get(features, "num_file_creations", 0)
    hot = _get(features, "hot", 0)
    num_access_files = _get(features, "num_access_files", 0)

    if land == 1:
        matches.append(RuleMatch(
            detection="Land attack (spoofed src=dst)",
            confidence=0.95,
            rationale="land flag set (source and destination address/port identical)",
        ))

    if num_failed_logins >= 3:
        matches.append(RuleMatch(
            detection="Credential guessing (SNMP/FTP/service auth)",
            confidence=min(1.0, 0.5 + num_failed_logins / 10),
            rationale=f"{num_failed_logins} failed logins observed on this flow",
        ))
    elif num_failed_logins >= 1 and logged_in == 0 and count > 5:
        matches.append(RuleMatch(
            detection="SSH/Telnet brute-force behaviour",
            confidence=0.6,
            rationale=(
                f"{num_failed_logins} failed login(s), not authenticated, "
                f"{count} connections to same host in window"
            ),
        ))

    # S0/REJ/SH with zero payload is a strong scan signal on its own -- a
    # real scan usually shows one such flow per probed port, no repeat
    # count needed
    if flag in ("S0", "REJ", "SH") and src_bytes == 0 and dst_bytes == 0:
        matches.append(RuleMatch(
            detection="Port scanning",
            confidence=min(0.95, 0.55 + count / 50),
            rationale=f"{count} connection(s) with flag={flag} and zero payload bytes",
        ))

    if serror_rate > 0.5 and count > 50:
        matches.append(RuleMatch(
            detection="Network denial-of-service pattern",
            confidence=min(1.0, serror_rate),
            rationale=f"serror_rate={serror_rate:.2f} across {count} connections",
        ))
    elif same_srv_rate > 0.9 and count > 200:
        matches.append(RuleMatch(
            detection="Network denial-of-service pattern",
            confidence=0.8,
            rationale=f"same_srv_rate={same_srv_rate:.2f} with {count} connections (flood pattern)",
        ))

    if root_shell == 1 or num_root > 0 or su_attempted > 0:
        matches.append(RuleMatch(
            detection="Privilege escalation indicators",
            confidence=0.85,
            rationale="root shell / su / num_root activity observed on this flow",
        ))

    if num_shells > 0 or num_file_creations > 2 or num_access_files > 2:
        matches.append(RuleMatch(
            detection="Suspicious remote command execution",
            confidence=0.6,
            rationale=(
                f"num_shells={num_shells}, num_file_creations={num_file_creations}, "
                f"num_access_files={num_access_files}"
            ),
        ))
    elif hot >= 2:
        # "hot" is NSL-KDD's own feature: count of system-directory access /
        # program creation indicators on this connection, not something we inferred
        matches.append(RuleMatch(
            detection="Suspicious remote command execution",
            confidence=0.55,
            rationale=f"hot={hot} system-access indicators on this connection",
        ))

    if dst_bytes > 500_000 and src_bytes < max(1, dst_bytes / 100):
        matches.append(RuleMatch(
            detection="Unusual outbound data volume",
            confidence=min(0.9, dst_bytes / 2_000_000),
            rationale=f"dst_bytes={dst_bytes} vastly exceeds src_bytes={src_bytes}",
        ))

    return matches
