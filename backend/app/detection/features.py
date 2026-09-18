"""Feature extraction.

SentinelFlow works on flow-level records (one row per network connection),
the same representation Zeek's conn.log or a NetFlow collector would hand
you. This module defines the numeric feature set used by both the rule
engine and the ML model, and converts a raw NSL-KDD-style CSV row (used for
ingestion/evaluation in scripts/load_dataset.py) into that shape.
"""

# Numeric columns used as the Isolation Forest's feature vector. Categorical
# columns (protocol_type, service, flag) are surfaced to the rule engine
# directly but are not fed to the ML model in this MVP (see docs/architecture.md
# roadmap for one-hot encoding categorical features).
NUMERIC_FEATURE_COLUMNS = [
    "duration",
    "src_bytes",
    "dst_bytes",
    "land",
    "wrong_fragment",
    "urgent",
    "hot",
    "num_failed_logins",
    "logged_in",
    "num_compromised",
    "root_shell",
    "su_attempted",
    "num_root",
    "num_file_creations",
    "num_shells",
    "num_access_files",
    "count",
    "srv_count",
    "serror_rate",
    "srv_serror_rate",
    "rerror_rate",
    "srv_rerror_rate",
    "same_srv_rate",
    "diff_srv_rate",
    "srv_diff_host_rate",
    "dst_host_count",
    "dst_host_srv_count",
    "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate",
    "dst_host_srv_serror_rate",
    "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate",
]

def numeric_vector(features: dict) -> list[float]:
    """Project a feature dict onto the fixed numeric vector the ML model expects."""
    return [float(features.get(col, 0) or 0) for col in NUMERIC_FEATURE_COLUMNS]
