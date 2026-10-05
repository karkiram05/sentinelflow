# Data

```
raw/KDDTest-21.txt                  public NSL-KDD file, untouched
  └─ sample/nsl_kdd_sample.csv      1,279-row stratified sample (max 60 rows per label)
       ├─ clean/nsl_kdd_sample_clean.csv     + header, row_id, attack_category, is_attack
       ├─ clean/data_quality_report.json     nulls, duplicates, range checks, provenance
       └─ processed/                         written by scripts/load_dataset.py
            ├─ train_split.csv               767 rows the Isolation Forest is fit on
            ├─ test_split.csv                512 held-out rows the metrics come from
            ├─ test_predictions.csv          one row per test flow: alert?, detection, severity, risk
            ├─ recall_by_label.csv           caught / total per attack label
            └─ alert_rate_by_category.csv    per DoS / Probe / R2L / U2R / normal
```

Rebuild everything from the raw file:

```bash
python scripts/build_data.py
python scripts/load_dataset.py --reset-db
python scripts/make_charts.py
```

## Raw data

| | |
|---|---|
| File | `raw/KDDTest-21.txt` |
| Dataset | NSL-KDD, Canadian Institute for Cybersecurity, University of New Brunswick (<https://www.unb.ca/cic/datasets/nsl.html>) |
| What it is | The `KDDTest-21` split: the NSL-KDD test records that 21 or fewer of the authors' 21 reference classifiers labelled correctly, i.e. the harder test records |
| Rows | 11,850 (9,698 attack, 2,152 normal), 38 distinct labels |
| SHA-256 | `746993ac9e25868827cacf09eab450050a2a1056e1ce48a1ad39f5dc801d531d` |
| Downloaded from | `https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTest-21.txt` and, as a cross-check, `https://raw.githubusercontent.com/jmnwong/NSL-KDD-Dataset/master/KDDTest-21.txt`. Both copies were byte-identical. |

`scripts/build_data.py` refuses to run if the checksum doesn't match.

**Citation.** M. Tavallaee, E. Bagheri, W. Lu and A. A. Ghorbani, "A
Detailed Analysis of the KDD CUP 99 Data Set," *IEEE Symposium on
Computational Intelligence for Security and Defense Applications (CISDA)*,
2009.

**Licence.** NSL-KDD is published by UNB for research use, with the paper
above as the requested citation. The UNB page could not be re-checked from
the environment these files were built in (its domain was blocked), so read
the current terms on that page before any use beyond research and
education.

## Columns

The 41 NSL-KDD features, then `label` (attack name or `normal`) and
`difficulty` (how many of the 21 reference classifiers got the record
right). Column names are in `scripts/nsl_kdd.py`. The clean file adds:

| Column | Meaning |
|---|---|
| `row_id` | 0-based line number in `sample/nsl_kdd_sample.csv`; the same id is used in `processed/` |
| `attack_category` | DoS, Probe, R2L (remote to local), U2R (user to root) or normal. This is the standard grouping from the NSL-KDD literature, defined in `scripts/nsl_kdd.py`; it is not a column of the raw file |
| `is_attack` | 1 unless the label is `normal` |

`processed/test_predictions.csv` adds `alerted`, `outcome` (TP/FP/TN/FN),
`detection`, `detection_source` (rule, ml or rule+ml), `mitre_technique`,
`confidence`, `risk_score` and `severity`.

## What the quality checks found

See `clean/data_quality_report.json`. In short: no nulls, no duplicate
rows, no rates outside [0, 1], no non-binary flags, no negative counts, so
no row was dropped or changed. One feature vector appears under two
different labels: that's label noise in NSL-KDD itself.

## What this data is not

NSL-KDD has no IP addresses. `load_dataset.py` assigns source and
destination IPs round-robin from a private range only so the per-device
views have something to group by. Those IPs are not part of the dataset
and mean nothing.
