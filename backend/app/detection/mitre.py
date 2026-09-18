"""Mapping from SentinelFlow detection names to MITRE ATT&CK techniques.

This is intentionally a small, honest mapping covering only the detections
the rule and ML engines actually produce — not a padded list of every
technique that sounds relevant. Extend this as new detections are added.
"""

MITRE_MAP = {
    "SSH/Telnet brute-force behaviour": ("T1110", "Brute Force"),
    "Credential guessing (SNMP/FTP/service auth)": ("T1110.001", "Password Guessing"),
    "Port scanning": ("T1046", "Network Service Scanning"),
    "Network denial-of-service pattern": ("T1498", "Network Denial of Service"),
    "Land attack (spoofed src=dst)": ("T1498", "Network Denial of Service"),
    "Privilege escalation indicators": ("T1068", "Exploitation for Privilege Escalation"),
    "Suspicious remote command execution": ("T1059", "Command and Scripting Interpreter"),
    "Unusual outbound data volume": ("T1030", "Data Transfer Size Limits"),
    # Deliberately NOT mapped: a pure statistical outlier from the Isolation
    # Forest, with no rule corroborating it, doesn't tell you *which*
    # technique is in play -- forcing a MITRE ID onto it would overstate
    # what an unsupervised anomaly score actually knows. It's still surfaced
    # as an alert (see engine.py); it just triages as "needs analyst review"
    # rather than a specific technique.
}


def lookup(detection_name: str) -> tuple[str | None, str | None]:
    return MITRE_MAP.get(detection_name, (None, None))
