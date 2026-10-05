#!/usr/bin/env python3
"""Draw the evaluation charts from the CSVs that scripts/load_dataset.py
exports to data/processed/. Every chart reads those files and nothing
else, so a figure can never disagree with the numbers behind it.

Usage:
    python scripts/load_dataset.py --reset-db   # writes data/processed/*.csv
    python scripts/make_charts.py               # writes docs/figures/*.png
"""
import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import pandas as pd  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
PROCESSED = REPO / "data" / "processed"
FIGURES = REPO / "docs" / "figures"

# Palette: light chart surface, recessive chrome, fixed categorical order.
SURFACE = "#fcfcfb"
INK = "#0b0b0b"
INK_2 = "#52514e"
MUTED = "#898781"
GRID = "#e1e0d9"
BASELINE = "#c3c2b7"
CATEGORY_COLOR = {"DoS": "#2a78d6", "Probe": "#eb6834", "R2L": "#1baf7a", "U2R": "#4a3aa7"}
SEVERITY_COLOR = {"CRITICAL": "#d03b3b", "HIGH": "#ec835a", "MEDIUM": "#fab219", "LOW": "#0ca30c"}
BLUE_RAMP = ["#cde2fb", "#86b6ef", "#3987e5", "#1c5cab", "#0d366b"]


def style():
    plt.rcParams.update({
        "figure.facecolor": SURFACE, "axes.facecolor": SURFACE, "savefig.facecolor": SURFACE,
        "axes.edgecolor": BASELINE, "axes.labelcolor": INK_2, "text.color": INK,
        "xtick.color": MUTED, "ytick.color": INK_2, "axes.grid": True,
        "grid.color": GRID, "grid.linewidth": 0.8, "axes.axisbelow": True,
        "axes.spines.top": False, "axes.spines.right": False,
        "font.family": "DejaVu Sans", "font.size": 10, "axes.titlesize": 12,
        "axes.titleweight": "bold", "axes.titlelocation": "left",
    })


def save(fig, name):
    FIGURES.mkdir(parents=True, exist_ok=True)
    path = FIGURES / name
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"Wrote {path.relative_to(REPO)}")


def confusion_matrix(pred: pd.DataFrame):
    counts = pred["outcome"].value_counts()
    grid = [[counts.get("TP", 0), counts.get("FN", 0)], [counts.get("FP", 0), counts.get("TN", 0)]]
    names = [["True positive", "False negative"], ["False positive", "True negative"]]
    fig, ax = plt.subplots(figsize=(5.6, 4.2))
    ax.grid(False)
    peak = max(max(row) for row in grid)
    for r in range(2):
        for c in range(2):
            value = grid[r][c]
            step = min(int(value / peak * (len(BLUE_RAMP) - 1) + 0.5), len(BLUE_RAMP) - 1)
            ax.add_patch(plt.Rectangle((c, 1 - r), 0.97, 0.97, color=BLUE_RAMP[step]))
            ink = "#ffffff" if step >= 2 else INK
            ax.text(c + 0.485, 1 - r + 0.56, f"{value}", ha="center", va="center",
                    fontsize=22, fontweight="bold", color=ink)
            ax.text(c + 0.485, 1 - r + 0.32, names[r][c], ha="center", va="center",
                    fontsize=9, color=ink)
    ax.set_xlim(0, 2)
    ax.set_ylim(0, 2)
    ax.set_xticks([0.485, 1.485], ["Alert raised", "No alert"])
    ax.set_yticks([1.485, 0.485], ["Attack\n(ground truth)", "Normal\n(ground truth)"])
    ax.tick_params(length=0)
    for spine in ax.spines.values():
        spine.set_visible(False)
    total = sum(sum(row) for row in grid)
    ax.set_title(f"Held-out test split, {total} flows")
    save(fig, "confusion_matrix.png")


def recall_by_category(pred: pd.DataFrame):
    attacks = pred[pred["is_attack"] == 1]
    table = attacks.groupby("attack_category")["alerted"].agg(["sum", "count"])
    table = table.loc[["DoS", "Probe", "R2L", "U2R"]]
    rates = table["sum"] / table["count"] * 100
    normal = pred[pred["is_attack"] == 0]
    fpr = normal["alerted"].mean() * 100

    fig, ax = plt.subplots(figsize=(7, 3.4))
    ax.grid(axis="y", visible=False)
    y = range(len(rates))
    ax.barh(list(y), rates.values, height=0.6,
            color=[CATEGORY_COLOR[c] for c in rates.index], edgecolor=SURFACE, linewidth=2)
    for i, (cat, rate) in enumerate(rates.items()):
        caught, total = int(table.loc[cat, "sum"]), int(table.loc[cat, "count"])
        ax.text(rate + 1.5, i, f"{rate:.0f}%  ({caught}/{total})", va="center", color=INK_2, fontsize=9)
    ax.set_yticks(list(y), rates.index)
    ax.invert_yaxis()
    ax.set_xlim(0, 100)
    ax.set_xlabel("Attacks detected (%)")
    ax.set_title("Detection rate by attack category")
    ax.text(0, -0.28, f"False positive rate on normal traffic: {fpr:.1f}% "
            f"({int(normal['alerted'].sum())} of {len(normal)} normal flows flagged)",
            transform=ax.transAxes, color=INK_2, fontsize=9)
    save(fig, "recall_by_category.png")


def recall_by_label(pred: pd.DataFrame):
    attacks = pred[pred["is_attack"] == 1]
    table = attacks.groupby(["label", "attack_category"])["alerted"].agg(["sum", "count"]).reset_index()
    # Labels with fewer than 5 test rows are left off: a rate over 1-4 flows
    # says little. They still count in every headline number.
    table = table[table["count"] >= 5].copy()
    table["rate"] = table["sum"] / table["count"] * 100
    table = table.sort_values(["rate", "count"], ascending=[True, True])

    fig, ax = plt.subplots(figsize=(7.5, 8.2))
    ax.grid(axis="y", visible=False)
    y = range(len(table))
    ax.barh(list(y), table["rate"], height=0.7,
            color=[CATEGORY_COLOR[c] for c in table["attack_category"]],
            edgecolor=SURFACE, linewidth=1.5)
    for i, row in enumerate(table.itertuples()):
        ax.text(row.rate + 1.5, i, f"{int(row.sum)}/{int(row.count)}", va="center",
                color=INK_2, fontsize=8)
    ax.set_yticks(list(y), table["label"])
    ax.set_xlim(0, 110)
    ax.set_xticks([0, 25, 50, 75, 100])
    ax.set_xlabel("Attacks detected (%)")
    ax.set_title("Detection rate by attack type (test split, types with 5+ flows)")
    handles = [plt.Rectangle((0, 0), 1, 1, color=CATEGORY_COLOR[c]) for c in CATEGORY_COLOR]
    ax.legend(handles, list(CATEGORY_COLOR), loc="lower right", frameon=True,
              facecolor=SURFACE, edgecolor=GRID, title="Category")
    save(fig, "recall_by_attack_type.png")


def severity_distribution(pred: pd.DataFrame):
    alerted = pred[pred["alerted"] == 1]
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    counts = alerted["severity"].value_counts().reindex(order, fill_value=0)
    by_truth = alerted.groupby(["severity", "is_attack"]).size().unstack(fill_value=0).reindex(order, fill_value=0)

    fig, ax = plt.subplots(figsize=(6.4, 3.6))
    ax.grid(axis="x", visible=False)
    ax.bar(order, counts.values, width=0.6, color=[SEVERITY_COLOR[s] for s in order],
           edgecolor=SURFACE, linewidth=2)
    for i, sev in enumerate(order):
        fp = int(by_truth.loc[sev, 0]) if 0 in by_truth.columns else 0
        label = f"{counts[sev]}" + (f"\n({fp} on normal)" if fp else "")
        ax.text(i, counts[sev] + 2, label, ha="center", va="bottom", color=INK_2, fontsize=9)
    ax.set_ylabel("Alerts")
    ax.set_ylim(0, counts.max() * 1.25 + 1)
    ax.set_title(f"Alert severity on the test split ({len(alerted)} alerts)")
    save(fig, "severity_distribution.png")


def main():
    style()
    pred = pd.read_csv(PROCESSED / "test_predictions.csv")
    report = json.loads((REPO / "docs" / "evaluation_report.json").read_text())
    # Guard: the CSV and the JSON report come from the same run.
    counts = pred["outcome"].value_counts()
    for key, outcome in (("true_positives", "TP"), ("false_positives", "FP"),
                         ("true_negatives", "TN"), ("false_negatives", "FN")):
        if int(counts.get(outcome, 0)) != report[key]:
            raise SystemExit(f"test_predictions.csv disagrees with evaluation_report.json on {key}; "
                             "rerun scripts/load_dataset.py --reset-db")
    confusion_matrix(pred)
    recall_by_category(pred)
    recall_by_label(pred)
    severity_distribution(pred)


if __name__ == "__main__":
    main()
