#!/usr/bin/env python3
"""Ingest the bundled NSL-KDD sample, run it through the full detection
pipeline (rules + Isolation Forest), and report real precision/recall
against the dataset's ground-truth labels.

This is the evidence step: it proves the detection engine actually catches
something, using real (if dated) labeled network intrusion data rather than
a self-generated traffic simulator. See docs/results.md for the numbers
this script produces and docs/architecture.md for the honest caveats
(NSL-KDD rows carry no source/destination IP, so IPs below are assigned
round-robin from a small private-range pool purely to demonstrate the
device-aggregation feature -- they are not part of the real dataset).

Usage:
    python scripts/load_dataset.py [--csv path] [--db sqlite:///./sentinelflow.db]
"""
import argparse
import itertools
import json
import sys
from pathlib import Path

import pandas as pd

BACKEND_DIR = Path(__file__).resolve().parent.parent / "backend"
sys.path.insert(0, str(BACKEND_DIR))

from app.database import Base, SessionLocal, engine  # noqa: E402
from app.detection.features import NUMERIC_FEATURE_COLUMNS  # noqa: E402
from app.ingest import record_event  # noqa: E402
from app.state import detection_state  # noqa: E402
from app import models  # noqa: E402,F401

NSL_KDD_COLUMNS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", "land",
    "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in", "num_compromised",
    "root_shell", "su_attempted", "num_root", "num_file_creations", "num_shells",
    "num_access_files", "num_outbound_cmds", "is_host_login", "is_guest_login", "count",
    "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate",
    "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate", "dst_host_count",
    "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
    "dst_host_srv_serror_rate", "dst_host_rerror_rate", "dst_host_srv_rerror_rate",
    "label", "difficulty",
]

# Demonstration-only IP pool; see module docstring.
SRC_IP_POOL = [f"192.168.1.{i}" for i in range(10, 40)]
DST_IP_POOL = [f"10.0.0.{i}" for i in range(5, 25)]


def row_to_features(row: pd.Series) -> dict:
    features = {col: row[col] for col in NUMERIC_FEATURE_COLUMNS}
    features["protocol_type"] = row["protocol_type"]
    features["service"] = row["service"]
    features["flag"] = row["flag"]
    return features


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--csv", default=str(Path(__file__).resolve().parent.parent / "data/sample/nsl_kdd_sample.csv"))
    parser.add_argument("--reset-db", action="store_true", help="Drop and recreate all tables first")
    args = parser.parse_args()

    if args.reset_db:
        Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)

    df = pd.read_csv(args.csv, names=NSL_KDD_COLUMNS)
    print(f"Loaded {len(df)} real NSL-KDD rows from {args.csv}")

    feature_dicts = [row_to_features(row) for _, row in df.iterrows()]

    # Fit the Isolation Forest unsupervised, on the numeric features only --
    # it never sees df["label"]. This mirrors how it would be fit on a batch
    # of live traffic in production.
    detection_state.fit(feature_dicts)
    print(f"Fit Isolation Forest on {len(feature_dicts)} flows (contamination={detection_state.anomaly_detector.contamination})")

    src_ips = itertools.cycle(SRC_IP_POOL)
    dst_ips = itertools.cycle(DST_IP_POOL)

    db = SessionLocal()
    tp = fp = tn = fn = 0
    try:
        for (_, row), features in zip(df.iterrows(), feature_dicts):
            ground_truth_attack = row["label"] != "normal"

            event_in = {
                "source_ip": next(src_ips),
                "destination_ip": next(dst_ips),
                "protocol": row["protocol_type"],
                "destination_port": None,
                "service": row["service"],
                "flag": row["flag"],
                "duration": float(row["duration"]),
                "src_bytes": int(row["src_bytes"]),
                "dst_bytes": int(row["dst_bytes"]),
                "features": features,
                "ground_truth_label": row["label"],
            }
            _event, alert = record_event(db, event_in)
            predicted_attack = alert is not None

            if predicted_attack and ground_truth_attack:
                tp += 1
            elif predicted_attack and not ground_truth_attack:
                fp += 1
            elif not predicted_attack and ground_truth_attack:
                fn += 1
            else:
                tn += 1
    finally:
        db.close()

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    accuracy = (tp + tn) / len(df) if len(df) else 0.0

    report = {
        "rows_evaluated": len(df),
        "true_positives": tp,
        "false_positives": fp,
        "true_negatives": tn,
        "false_negatives": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "accuracy": round(accuracy, 4),
    }
    print(json.dumps(report, indent=2))

    report_path = Path(__file__).resolve().parent.parent / "docs" / "evaluation_report.json"
    report_path.write_text(json.dumps(report, indent=2))
    print(f"\nWrote {report_path}")


if __name__ == "__main__":
    main()
