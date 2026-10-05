#!/usr/bin/env python3
"""Rebuild the clean dataset from the raw NSL-KDD file, and prove where the
bundled sample came from.

Pipeline (each step writes a file, nothing is hand-edited):

    data/raw/KDDTest-21.txt            raw, untouched public file (checksum-pinned)
      -> data/sample/nsl_kdd_sample.csv  the 1,279-row stratified sample the
                                        evaluation runs on (already in the repo)
      -> data/clean/nsl_kdd_sample_clean.csv   named columns, attack category,
                                        is_attack flag, row_id
      -> data/clean/data_quality_report.json   row counts, nulls, duplicates,
                                        range checks, provenance result

The sample was written by pandas, which serialises 0.00 as 0.0, so a
byte-for-byte line match against the raw file finds nothing. Rows are
compared after parsing every numeric field as a float instead; with that,
every sample row is found in the raw file.

Usage:
    python scripts/build_data.py
"""
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path

import pandas as pd

REPO = Path(__file__).resolve().parent.parent
RAW = REPO / "data" / "raw" / "KDDTest-21.txt"
SAMPLE = REPO / "data" / "sample" / "nsl_kdd_sample.csv"
CLEAN_DIR = REPO / "data" / "clean"

# SHA-256 of KDDTest-21.txt as downloaded from two independent public
# mirrors (see data/README.md); both copies were byte-identical.
RAW_SHA256 = "746993ac9e25868827cacf09eab450050a2a1056e1ce48a1ad39f5dc801d531d"

sys.path.insert(0, str(Path(__file__).resolve().parent))
from nsl_kdd import ATTACK_CATEGORY, NSL_KDD_COLUMNS  # noqa: E402


RATE_COLUMNS = [c for c in NSL_KDD_COLUMNS if c.endswith("_rate")]
BINARY_COLUMNS = ["land", "logged_in", "is_host_login", "is_guest_login"]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 16), b""):
            digest.update(block)
    return digest.hexdigest()


def normalise(line: str) -> tuple:
    out = []
    for token in line.strip().split(","):
        try:
            out.append(float(token))
        except ValueError:
            out.append(token)
    return tuple(out)


def main() -> int:
    if not RAW.exists():
        print(f"Missing {RAW}. See data/README.md for where to download it.")
        return 1
    raw_hash = sha256(RAW)
    if raw_hash != RAW_SHA256:
        print(f"Checksum mismatch for {RAW}: {raw_hash} (expected {RAW_SHA256})")
        return 1
    print(f"Raw file checksum OK ({RAW.name}, sha256 {raw_hash[:16]}...)")

    raw_lines = RAW.read_text().splitlines()
    raw_rows = Counter(normalise(line) for line in raw_lines if line.strip())
    sample_lines = [line for line in SAMPLE.read_text().splitlines() if line.strip()]
    missing = [i for i, line in enumerate(sample_lines) if normalise(line) not in raw_rows]
    print(f"Provenance: {len(sample_lines) - len(missing)} of {len(sample_lines)} "
          f"sample rows found in {RAW.name}")
    if missing:
        print(f"Rows not found in the raw file (0-based): {missing[:20]}")
        return 1

    df = pd.read_csv(SAMPLE, names=NSL_KDD_COLUMNS)
    unknown = sorted(set(df["label"]) - set(ATTACK_CATEGORY))
    if unknown:
        print(f"Labels with no attack category mapping: {unknown}")
        return 1

    raw_df = pd.read_csv(RAW, names=NSL_KDD_COLUMNS)

    df.insert(0, "row_id", range(len(df)))
    df["attack_category"] = df["label"].map(ATTACK_CATEGORY)
    df["is_attack"] = (df["label"] != "normal").astype(int)

    range_problems = {}
    for col in RATE_COLUMNS:
        bad = int(((df[col] < 0) | (df[col] > 1)).sum())
        if bad:
            range_problems[col] = bad
    for col in BINARY_COLUMNS:
        bad = int((~df[col].isin([0, 1])).sum())
        if bad:
            range_problems[col] = bad
    negative = {
        col: int((df[col] < 0).sum())
        for col in ("duration", "src_bytes", "dst_bytes", "count", "srv_count")
        if (df[col] < 0).any()
    }
    range_problems.update(negative)

    feature_cols = [c for c in NSL_KDD_COLUMNS if c not in ("label", "difficulty")]
    report = {
        "raw_file": f"data/raw/{RAW.name}",
        "raw_sha256": raw_hash,
        "raw_rows": len(raw_df),
        "raw_distinct_labels": int(raw_df["label"].nunique()),
        "raw_attack_rows": int((raw_df["label"] != "normal").sum()),
        "raw_normal_rows": int((raw_df["label"] == "normal").sum()),
        "sample_file": "data/sample/nsl_kdd_sample.csv",
        "sample_rows": len(df),
        "sample_rows_found_in_raw": len(sample_lines) - len(missing),
        "sample_distinct_labels": int(df["label"].nunique()),
        "sample_max_rows_per_label": int(df["label"].value_counts().max()),
        "null_values": int(df.isna().sum().sum()),
        "duplicate_rows_full": int(df.drop(columns="row_id").duplicated().sum()),
        "duplicate_feature_vectors_with_different_labels": int(
            df.groupby(feature_cols)["label"].nunique().gt(1).sum()
        ),
        "out_of_range_values": range_problems,
        "rows_by_category": df["attack_category"].value_counts().sort_index().to_dict(),
        "rows_by_label": df["label"].value_counts().sort_index().to_dict(),
        "cleaning_steps": [
            "verified raw file SHA-256 against the pinned value",
            "verified every sample row exists in the raw file (numeric fields compared as floats)",
            "added the 43 NSL-KDD column names as a header",
            "added row_id (0-based line number in data/sample/nsl_kdd_sample.csv)",
            "added attack_category (DoS / Probe / R2L / U2R / normal) and is_attack",
            "checked for nulls, duplicate rows, rates outside [0, 1], non-binary flags and negative counts",
        ],
    }
    if report["null_values"] == 0 and not range_problems:
        report["cleaning_steps"].append(
            "no rows were dropped or altered: the checks found no nulls or out-of-range values"
        )
    else:
        report["cleaning_steps"].append(
            "WARNING: the checks above found problems; rows were kept as-is, see null_values and out_of_range_values"
        )

    CLEAN_DIR.mkdir(parents=True, exist_ok=True)
    clean_path = CLEAN_DIR / "nsl_kdd_sample_clean.csv"
    df.to_csv(clean_path, index=False)
    report_path = CLEAN_DIR / "data_quality_report.json"
    report_path.write_text(json.dumps(report, indent=2) + "\n")
    print(f"Wrote {clean_path.relative_to(REPO)} ({len(df)} rows, {df.shape[1]} columns)")
    print(f"Wrote {report_path.relative_to(REPO)}")
    print(json.dumps({k: report[k] for k in (
        "null_values", "duplicate_rows_full",
        "duplicate_feature_vectors_with_different_labels", "out_of_range_values",
        "rows_by_category")}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
