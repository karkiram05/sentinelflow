#!/usr/bin/env python3
"""Ingest the bundled NSL-KDD sample, run it through the full detection
pipeline (rules + Isolation Forest), and report precision/recall against
the dataset's ground-truth labels, computed on a held-out test split the
Isolation Forest never saw during fitting. See docs/results.md for the
numbers this produces and docs/architecture.md for caveats (NSL-KDD rows
carry no source/destination IP, so IPs below are assigned round-robin from
a small private-range pool purely to exercise device aggregation -- they
aren't part of the real dataset).

The repeat-offender risk boost is switched off here for the same reason:
with round-robin IPs, "prior alerts from this source" would just reflect
the IP pool, not real repeat behaviour.

Usage:
    python scripts/load_dataset.py [--csv path] [--reset-db]

Set DATABASE_URL to seed a different database (e.g. the Docker Compose
Postgres instance); by default it uses the same SQLite file as the API.
"""
import argparse
import itertools
import json
from collections import Counter
import sys
from pathlib import Path

import pandas as pd
from sklearn.model_selection import train_test_split

BACKEND_DIR = Path(__file__).resolve().parent.parent / "backend"
sys.path.insert(0, str(BACKEND_DIR))

from app.database import Base, SessionLocal, engine  # noqa: E402
from app.detection.features import NUMERIC_FEATURE_COLUMNS  # noqa: E402
from app.ingest import record_event  # noqa: E402
from app.state import detection_state  # noqa: E402
from app import models  # noqa: E402,F401

sys.path.insert(0, str(Path(__file__).resolve().parent))
from nsl_kdd import ATTACK_CATEGORY, NSL_KDD_COLUMNS  # noqa: E402

PROCESSED_DIR = Path(__file__).resolve().parent.parent / "data" / "processed"


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
    # row_id = 0-based line number in the sample file, so every exported
    # prediction can be traced back to its source row.
    df.index.name = "row_id"
    print(f"Loaded {len(df)} real NSL-KDD rows from {args.csv}")

    # Stratified split by label so both splits cover the same attack
    # categories in roughly the same proportion. A handful of labels in
    # this sample have exactly one row (can't be stratified into two
    # non-empty splits) -- those go into the fit split only, and are
    # excluded from the test split and therefore from the reported metrics.
    label_counts = df["label"].value_counts()
    rare_labels = label_counts[label_counts < 2].index.tolist()
    splittable = df[~df["label"].isin(rare_labels)]
    rare_rows = df[df["label"].isin(rare_labels)]
    if rare_labels:
        print(f"Note: {len(rare_rows)} row(s) with singleton label(s) {rare_labels} "
              f"go into the fit split only (can't be stratified).")

    train_df, test_df = train_test_split(
        splittable, test_size=0.4, random_state=42, stratify=splittable["label"],
    )
    train_df = pd.concat([train_df, rare_rows])
    print(f"Split: {len(train_df)} rows to fit the Isolation Forest, "
          f"{len(test_df)} held out for evaluation.")

    train_features = [row_to_features(row) for _, row in train_df.iterrows()]

    # Fit unsupervised on the train split's numeric features only -- no
    # labels, and no exposure to the test split's feature distribution.
    detection_state.fit(train_features)
    print(f"Fit Isolation Forest on {len(train_features)} flows (contamination={detection_state.anomaly_detector.contamination})")

    src_ips = itertools.cycle(SRC_IP_POOL)
    dst_ips = itertools.cycle(DST_IP_POOL)

    def ingest_split(db, split_df, *, is_test: bool):
        nonlocal tp, fp, tn, fn, severity_counts
        for row_id, row in split_df.iterrows():
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
                "features": row_to_features(row),
                "ground_truth_label": row["label"],
            }
            _event, alert = record_event(db, event_in, apply_repeat_boost=False)
            if not is_test:
                continue
            predictions.append({
                "row_id": row_id,
                "label": row["label"],
                "attack_category": ATTACK_CATEGORY.get(row["label"], "unknown"),
                "difficulty": int(row["difficulty"]),
                "is_attack": int(ground_truth_attack),
                "alerted": int(alert is not None),
                "outcome": (
                    ("TP" if ground_truth_attack else "FP") if alert is not None
                    else ("FN" if ground_truth_attack else "TN")
                ),
                "detection": alert.detection if alert else "",
                "detection_source": alert.detection_source if alert else "",
                "mitre_technique": (alert.mitre_technique or "") if alert else "",
                "confidence": alert.confidence if alert else None,
                "risk_score": alert.risk_score if alert else None,
                "severity": alert.severity if alert else "",
            })
            if alert is not None:
                severity_counts[alert.severity] += 1
            predicted_attack = alert is not None
            if predicted_attack and ground_truth_attack:
                tp += 1
            elif predicted_attack and not ground_truth_attack:
                fp += 1
            elif not predicted_attack and ground_truth_attack:
                fn += 1
            else:
                tn += 1

    db = SessionLocal()
    tp = fp = tn = fn = 0
    severity_counts = Counter()
    predictions = []
    try:
        # Ingest the fit split first (populates the DB/dashboard, no metrics
        # counted), then the held-out test split (metrics counted here).
        ingest_split(db, train_df, is_test=False)
        ingest_split(db, test_df, is_test=True)
    finally:
        db.close()

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    accuracy = (tp + tn) / len(test_df) if len(test_df) else 0.0
    normal_rows = tn + fp
    attack_rows = tp + fn
    false_positive_rate = fp / normal_rows if normal_rows else 0.0
    # What precision a detector that alerts on every single flow would get on
    # this split. On an attack-heavy sample this is already very high, so
    # headline precision has to be read against it.
    baseline_precision_alert_on_everything = attack_rows / len(test_df) if len(test_df) else 0.0

    report = {
        "methodology": "stratified train/test split; Isolation Forest fit on train only, metrics computed on held-out test split only",
        "rows_total": len(df),
        "rows_fit_split": len(train_df),
        "rows_test_split": len(test_df),
        "rows_evaluated": len(test_df),
        "true_positives": tp,
        "false_positives": fp,
        "true_negatives": tn,
        "false_negatives": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "accuracy": round(accuracy, 4),
        "test_split_attack_rows": attack_rows,
        "test_split_normal_rows": normal_rows,
        "false_positive_rate": round(false_positive_rate, 4),
        "baseline_precision_alert_on_everything": round(baseline_precision_alert_on_everything, 4),
        "test_split_alerts_by_severity": {
            band: severity_counts.get(band, 0) for band in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
        },
    }
    print(json.dumps(report, indent=2))

    report_path = Path(__file__).resolve().parent.parent / "docs" / "evaluation_report.json"
    report_path.write_text(json.dumps(report, indent=2) + "\n")
    print(f"\nWrote {report_path}")

    export_processed(train_df, test_df, predictions)


def export_processed(train_df, test_df, predictions):
    """Write the exact splits and per-flow predictions behind the report, so
    every number in docs/results.md can be recomputed from a CSV."""
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    for name, split in (("train_split.csv", train_df), ("test_split.csv", test_df)):
        out = split.copy()
        out["attack_category"] = out["label"].map(ATTACK_CATEGORY)
        out.sort_index().to_csv(PROCESSED_DIR / name)

    pred_df = pd.DataFrame(predictions).sort_values("row_id")
    pred_df.to_csv(PROCESSED_DIR / "test_predictions.csv", index=False)

    attacks = pred_df[pred_df["is_attack"] == 1]
    per_label = (
        attacks.groupby(["label", "attack_category"])["alerted"]
        .agg(caught="sum", total="count").reset_index()
    )
    per_label["recall"] = (per_label["caught"] / per_label["total"]).round(4)
    per_label.sort_values(["recall", "total"], ascending=[False, False]).to_csv(
        PROCESSED_DIR / "recall_by_label.csv", index=False)

    per_cat = (
        pred_df.groupby("attack_category")["alerted"]
        .agg(alerted="sum", total="count").reset_index()
    )
    per_cat["alert_rate"] = (per_cat["alerted"] / per_cat["total"]).round(4)
    per_cat.to_csv(PROCESSED_DIR / "alert_rate_by_category.csv", index=False)
    print(f"Wrote splits, per-flow predictions and recall tables to {PROCESSED_DIR}")


if __name__ == "__main__":
    main()
