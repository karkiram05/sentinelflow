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
normal traffic).

Reproduce with:

```bash
pip install -r backend/requirements.txt
python scripts/load_dataset.py --reset-db
```

## Methodology: held-out evaluation, not self-evaluation

The Isolation Forest is fit on a stratified 60% training split of this
sample and evaluated only on the remaining 40% held-out test split -- it
never sees the feature distribution of the rows the numbers below are
computed from. (One label with a single row can't be stratified into two
non-empty splits; that row goes into the fit split only and is excluded
from both the test split and these metrics -- see the script's comments.)

An earlier version of this evaluation fit the Isolation Forest on the full
dataset and then evaluated it on that same data. That is evaluation
leakage: the model never saw ground-truth labels (it's unsupervised), but
it did see the exact statistical shape of every point it was later
"tested" against, which can inflate apparent anomaly-detection performance.
The numbers below are the corrected, held-out figures. In this case fixing
the leakage barely moved the headline numbers, because most of what
SentinelFlow catches comes from the deterministic rule engine (which has
no notion of a training set at all, so nothing about it could leak) rather
than the Isolation Forest -- but the *methodology* is what makes that a
verifiable claim rather than an assumption.

## Headline numbers

| Metric | Value |
|---|---|
| Rows in sample | 1,279 (767 fit split, 512 held-out test split) |
| Precision (test split) | **96.2%** |
| Recall (test split) | **46.9%** |
| F1 score | 0.63 |
| True positives / False positives | 229 / 9 |
| False negatives / True negatives | 259 / 15 |

*(Regenerate `docs/evaluation_report.json` by rerunning
`python scripts/load_dataset.py --reset-db` -- these numbers are not
hand-edited.)*

## Reading these numbers honestly

**96.2% precision is a property of this evaluation sample, not a
production guarantee.** This sample's test split is roughly 95% attack
traffic (only 24 of 512 rows are labeled `normal`) because it was built to
preserve all 38 attack categories at a usable sample size, not to mirror a
real network's traffic mix. Real production traffic is overwhelmingly
benign -- typically single-digit percentages of it are actually malicious.
Precision is highly sensitive to that base rate: the same detector run
against traffic with a much lower attack prevalence will produce
proportionally more false positives per true positive, because there are
so many more benign flows for any given false-positive rate to apply to.
So the correct claim is: *on this attack-heavy 512-row held-out NSL-KDD
sample, SentinelFlow's alerts were correct 96.2% of the time.* That is a
real, honestly-measured number and a useful regression/demo signal -- it is
not a claim about what precision would look like pointed at a live
production network, and shouldn't be read as one.

**Recall is the honest cost of conservative thresholds, and of per-flow
detection.** Just over half of labeled attacks in the test split are
missed. Broken down by attack category, the pattern is not random:

| Attack pattern | Typical detection rate | Why |
|---|---|---|
| Port/network scans (`nmap`, `land`), floods/single-flow exploits (`back`, `mscan`, `buffer_overflow`) | 85-100% | These show a strong signal *within a single flow* -- exactly what the rule engine is built to catch |
| Multi-connection probes (`satan`, `smurf`, `neptune`, `warezmaster`, `portsweep`, `saint`) | 55-80% | Partially visible per-flow; SentinelFlow catches the more overt attempts |
| Slow/low-and-slow attacks (`guess_passwd`, `snmpguess`, `ipsweep`, `mailbomb`, `processtable`, `teardrop`, `snmpgetattack`) | 0% | These only become visible when you correlate *many* flows from the same source over a time window. SentinelFlow's MVP is deliberately per-flow (see `docs/architecture.md`), so it structurally cannot see this pattern yet -- this isn't a bug, it's a scoped-out feature (cross-flow/session correlation is the top roadmap item) |

Full per-category breakdown on the held-out test split (rows with fewer
than a handful of test-split examples, like `imap`, are excluded here
because a rate computed over 1-2 rows isn't meaningful; they're still
counted correctly in the headline TP/FP/TN/FN above):

| Attack label | Caught | Total (test split) | Rate |
|---|---|---|---|
| nmap | 24 | 24 | 100% |
| land | 3 | 3 | 100% |
| back | 23 | 24 | 96% |
| mscan | 21 | 24 | 88% |
| buffer_overflow | 7 | 8 | 88% |
| httptunnel | 20 | 24 | 83% |
| sendmail | 5 | 6 | 83% |
| neptune | 19 | 24 | 79% |
| satan | 18 | 24 | 75% |
| smurf | 15 | 24 | 62% |
| xterm | 3 | 5 | 60% |
| rootkit | 3 | 5 | 60% |
| warezmaster | 14 | 24 | 58% |
| portsweep | 14 | 24 | 58% |
| saint | 14 | 24 | 58% |
| apache2 | 13 | 24 | 54% |
| named | 3 | 7 | 43% |
| xlock | 1 | 4 | 25% |
| pod | 3 | 16 | 19% |
| multihop | 1 | 7 | 14% |
| guess_passwd | 0 | 24 | 0% |
| snmpguess | 0 | 24 | 0% |
| mailbomb | 0 | 24 | 0% |
| ipsweep | 0 | 24 | 0% |
| processtable | 0 | 24 | 0% |
| teardrop | 0 | 5 | 0% |
| snmpgetattack | 0 | 24 | 0% |

Of the 24 `normal` (non-attack) rows in the test split, 9 were flagged --
these 9 are exactly the 9 false positives in the headline numbers above.

## Why this table belongs in a portfolio project

A checklist README that claims a detection system "works" without showing
what it actually catches and misses is not evidence of anything. This
table is the difference between "I wired up scikit-learn" and "I understand
the failure modes of the thing I built" -- which is closer to what the
detection-engineering side of a SOC/cybersecurity role actually involves.

## A note on the input format

The features these rules and the Isolation Forest key on (`root_shell`,
`num_failed_logins`, `hot`, `num_file_creations`, and similar) are
NSL-KDD/KDD-Cup-style engineered connection features, not raw fields a
NetFlow record or a Zeek `conn.log` line gives you directly. A production
deployment of this detection logic against real flow telemetry would need
an adapter layer that derives these engineered features from whatever the
actual telemetry source provides (Zeek's connection and protocol logs,
NetFlow/IPFIX records, or host/auth logs, depending on deployment) --
that adapter does not exist in this MVP. `POST /events` accepts a
`features` dict shaped like these engineered NSL-KDD fields because that's
what the evaluation dataset, and therefore the rule thresholds tuned
against it, are built on. This is stated explicitly here (and in
`docs/architecture.md`'s roadmap) so the scope is clear rather than implied
by a README that talks about "flow telemetry" without saying which kind.
