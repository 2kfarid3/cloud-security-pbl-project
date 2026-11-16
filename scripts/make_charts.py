#!/usr/bin/env python3
"""Generate the two Phase 5 result charts from results/phase5_evaluation.md's numbers,
via scripts/evaluate_matrix.py's own computation (not re-typed by hand), so the charts
and the written report always come from the same measured numbers.

Usage: make_charts.py <results_csv> <out_dir>
"""
import csv
import sys

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import matplotlib.ticker as mticker  # noqa: E402

sys.path.insert(0, __file__.rsplit("/", 1)[0])
import metrics  # noqa: E402
from evaluate_matrix import BASELINE_POSITIVE_RULES, COMBINED_POSITIVE_RULES, parse_rules_fired  # noqa: E402

BLUE = "#2a78d6"
ORANGE = "#eb6834"
TEXT_PRIMARY = "#0b0b0b"
TEXT_SECONDARY = "#52514e"


def tally(rows, positive_rules):
    t = {"TP": 0, "FP": 0, "FN": 0, "TN": 0}
    for r in rows:
        fired = parse_rules_fired(r["rules_fired"])
        positive = bool(fired & positive_rules)
        cls = metrics.classify_run(r["expected_class"], r["validity"], positive)
        if cls in t:
            t[cls] += 1
    return t


def main():
    results_csv, out_dir = sys.argv[1], sys.argv[2]
    with open(results_csv, newline="") as fh:
        rows = list(csv.DictReader(fh))

    baseline_t = tally(rows, BASELINE_POSITIVE_RULES)
    combined_t = tally(rows, COMBINED_POSITIVE_RULES)
    n = len(rows)

    baseline_m = metrics.compute_metrics(**{k.lower(): v for k, v in baseline_t.items()})
    combined_m = metrics.compute_metrics(**{k.lower(): v for k, v in combined_t.items()})

    plt.rcParams.update({
        "font.size": 12,
        "axes.edgecolor": "#c9c8c0",
        "axes.labelcolor": TEXT_SECONDARY,
        "text.color": TEXT_PRIMARY,
        "xtick.color": TEXT_SECONDARY,
        "ytick.color": TEXT_SECONDARY,
    })

    # --- Chart 1: confusion-matrix counts, baseline vs combined ---
    labels = ["TP", "FP", "FN", "TN"]
    baseline_vals = [baseline_t[l] for l in labels]
    combined_vals = [combined_t[l] for l in labels]

    fig, ax = plt.subplots(figsize=(7, 4.5), dpi=150)
    x = range(len(labels))
    width = 0.34
    bars1 = ax.bar([i - width / 2 for i in x], baseline_vals, width, label="Baseline only", color=BLUE)
    bars2 = ax.bar([i + width / 2 for i in x], combined_vals, width, label="Baseline + Improved", color=ORANGE)
    for bars in (bars1, bars2):
        for b in bars:
            h = b.get_height()
            ax.annotate(f"{int(h)}", (b.get_x() + b.get_width() / 2, h), xytext=(0, 3),
                        textcoords="offset points", ha="center", fontsize=11, color=TEXT_PRIMARY)
    ax.set_xticks(list(x))
    ax.set_xticklabels(labels)
    ax.set_ylabel("Run count")
    ax.set_title(f"Category 1 confusion-matrix counts, baseline vs. baseline+improved\n"
                 f"n = {n} runs (13 test-matrix cases × 3 repetitions each)", fontsize=12)
    ax.spines[["top", "right"]].set_visible(False)
    ax.legend(frameon=False, loc="upper right")
    ax.yaxis.set_major_locator(mticker.MaxNLocator(integer=True))
    fig.tight_layout()
    fig.savefig(f"{out_dir}/confusion_counts.png")
    plt.close(fig)

    # --- Chart 2: precision/recall/F1/FPR, baseline vs combined ---
    metric_labels = ["Precision", "Recall", "F1", "False Positive\nRate"]
    baseline_vals = [baseline_m["precision"], baseline_m["recall"], baseline_m["f1"], baseline_m["false_positive_rate"]]
    combined_vals = [combined_m["precision"], combined_m["recall"], combined_m["f1"], combined_m["false_positive_rate"]]

    fig, ax = plt.subplots(figsize=(7.5, 4.5), dpi=150)
    x = range(len(metric_labels))
    bars1 = ax.bar([i - width / 2 for i in x], baseline_vals, width, label="Baseline only", color=BLUE)
    bars2 = ax.bar([i + width / 2 for i in x], combined_vals, width, label="Baseline + Improved", color=ORANGE)
    for bars in (bars1, bars2):
        for b in bars:
            h = b.get_height()
            ax.annotate(f"{h:.2f}", (b.get_x() + b.get_width() / 2, h), xytext=(0, 3),
                        textcoords="offset points", ha="center", fontsize=11, color=TEXT_PRIMARY)
    ax.set_xticks(list(x))
    ax.set_xticklabels(metric_labels)
    ax.set_ylim(0, 1.08)
    ax.set_ylabel("Score (0-1)")
    ax.set_title(f"Category 1 detection metrics, baseline vs. baseline+improved\n"
                 f"n = {n} runs (13 test-matrix cases × 3 repetitions each)", fontsize=12)
    ax.spines[["top", "right"]].set_visible(False)
    ax.legend(frameon=False, loc="upper right")
    fig.tight_layout()
    fig.savefig(f"{out_dir}/metrics_comparison.png")
    plt.close(fig)

    print(f"Wrote {out_dir}/confusion_counts.png and {out_dir}/metrics_comparison.png")
    print("baseline:", baseline_t, baseline_m)
    print("combined:", combined_t, combined_m)


if __name__ == "__main__":
    main()
