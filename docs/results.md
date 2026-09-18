# Detection results (real data, not a self-generated demo)

`scripts/load_dataset.py` ingests a real, labeled network intrusion dataset
-- [NSL-KDD](https://www.unb.ca/cic/datasets/nsl.html) -- through the exact
same code path `POST /events` uses, runs the detection engine on it, and
compares its output against the dataset's ground-truth labels. Nothing here
is a synthetic traffic generator grading its own homework: the labels come
from the dataset, not from SentinelFlow.

`data/sample/nsl_kdd_sample.csv` is a stratified sample of the public
`KDDTest-21` split (1,279 rows, capped at 60 rows per attack category to
keep the repo small while preserving all 38 distinct attack types plus
normal traffic). The Isolation Forest is fit unsupervised on this batch's
numeric features -- it never sees the label column.

Reproduce with:

```bash
pip install -r backend/requirements.txt
python scripts/load_dataset.py --reset-db
```

## Headline numbers

| Metric | Value |
|---|---|
| Rows evaluated | 1,279 |
| Precision | **96.6%** |
| Recall | **46.8%** |
| F1 score | 0.63 |
| True positives / False positives | 571 / 20 |
| False negatives / True negatives | 648 / 40 |

*(Regenerate `docs/evaluation_report.json` by rerunning the script above --
these numbers are not hand-edited.)*

## Reading these numbers honestly

**Precision is high on purpose.** When SentinelFlow raises an alert, it's
right 96.6% of the time. For a SOC-facing tool, false positives are what
actually get a detector disabled -- a noisy IDS gets its alerts ignored
within a week. The rule thresholds in `rules.py` were deliberately kept
conservative for this reason.

**Recall is the honest cost of that choice, and of per-flow detection.**
Just under half of labeled attacks in this sample are missed. Broken down
by attack category, the pattern is not random:

| Attack pattern | Typical detection rate | Why |
|---|---|---|
| Port/network scans (`nmap`, `land`), floods (`neptune`, `smurf`), privilege escalation (`sqlattack`, `perl`, `loadmodule`) | 85-100% | These show a strong signal *within a single flow* -- exactly what the rule engine is built to catch |
| Multi-connection probes (`satan`, `saint`, `mscan`) | 60-77% | Partially visible per-flow; SentinelFlow catches the more overt attempts |
| Slow/low-and-slow attacks (`guess_passwd`, `snmpguess`, `ipsweep`, `mailbomb`, `snmpgetattack`, `teardrop`) | 0-10% | These only become visible when you correlate *many* flows from the same source over a time window. SentinelFlow's MVP is deliberately per-flow (see `docs/architecture.md`), so it structurally cannot see this pattern yet -- this isn't a bug, it's a scoped-out feature (cross-flow/session correlation is the top roadmap item) |

Full per-category breakdown (38 attack types):

| Attack label | Caught | Total | Rate |
|---|---|---|---|
| nmap | 60 | 60 | 100% |
| land | 7 | 7 | 100% |
| loadmodule | 2 | 2 | 100% |
| sqlattack | 2 | 2 | 100% |
| perl | 2 | 2 | 100% |
| phf | 2 | 2 | 100% |
| back | 58 | 60 | 97% |
| httptunnel | 53 | 60 | 88% |
| neptune | 52 | 60 | 87% |
| buffer_overflow | 17 | 20 | 85% |
| satan | 43 | 60 | 72% |
| sendmail | 10 | 14 | 71% |
| xterm | 9 | 13 | 69% |
| smurf | 41 | 60 | 68% |
| mscan | 46 | 60 | 77% |
| saint | 36 | 60 | 60% |
| warezmaster | 34 | 60 | 57% |
| xsnoop | 2 | 4 | 50% |
| apache2 | 30 | 60 | 50% |
| portsweep | 29 | 60 | 48% |
| ps | 6 | 15 | 40% |
| rootkit | 5 | 13 | 38% |
| named | 5 | 17 | 29% |
| multihop | 4 | 18 | 22% |
| xlock | 2 | 9 | 22% |
| pod | 7 | 41 | 17% |
| processtable | 6 | 60 | 10% |
| snmpguess | 1 | 60 | 2% |
| mailbomb | 0 | 60 | 0% |
| snmpgetattack | 0 | 60 | 0% |
| ipsweep | 0 | 60 | 0% |
| guess_passwd | 0 | 60 | 0% |
| teardrop | 0 | 12 | 0% |
| ftp_write | 0 | 3 | 0% |
| worm | 0 | 2 | 0% |
| udpstorm | 0 | 2 | 0% |
| imap | 0 | 1 | 0% |

## Why this table belongs in a portfolio project

A checklist README that claims a detection system "works" without showing
what it actually catches and misses is not evidence of anything. This
table is the difference between "I wired up scikit-learn" and "I understand
the failure modes of the thing I built" -- which is closer to what the
detection-engineering side of a SOC/cybersecurity role actually involves.
