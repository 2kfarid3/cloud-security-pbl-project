#!/usr/bin/env python3
"""Score every run in a parse_falco_events.py results CSV against two views of the
rule set -- "baseline only" and "baseline+improved" -- so Phase 5 can show what the
improved rules actually changed, not just what the combined system now does.

A run's "positive signal" is pre-registered here as a fixed set of Warning-priority,
attack-indicating rule names (see docs/methodology.md: an Informational "normal" rule
firing is never itself a positive detection). This mirrors, rather than replaces,
each case's own expected_signal in tests/test_matrix.csv.

Usage: evaluate_matrix.py <results_csv> <scored_output_csv>
"""
import csv
import sys

sys.path.insert(0, __file__.rsplit("/", 1)[0])
import metrics  # noqa: E402

BASELINE_POSITIVE_RULES = {
    "PBL OpenMetadata Environment Discovery",
    "PBL OpenMetadata ServiceAccount Token Access",
    "PBL OpenMetadata Payload Execution",
}
IMPROVED_ADDITIONAL_RULES = {
    "PBL Improved Script Execution From Tmp",
    "PBL Improved ServiceAccount Token Access Any Tool",
}
COMBINED_POSITIVE_RULES = BASELINE_POSITIVE_RULES | IMPROVED_ADDITIONAL_RULES


def parse_rules_fired(rules_fired: str) -> set:
    if not rules_fired:
        return set()
    names = set()
    for part in rules_fired.split(";"):
        name = part.rsplit("=", 1)[0]
        names.add(name)
    return names


def main():
    results_csv, output_csv = sys.argv[1], sys.argv[2]

    with open(results_csv, newline="") as fh:
        runs = list(csv.DictReader(fh))

    scored = []
    tallies = {"baseline": {"TP": 0, "FP": 0, "FN": 0, "TN": 0, "INVALID": 0},
               "combined": {"TP": 0, "FP": 0, "FN": 0, "TN": 0, "INVALID": 0}}

    for run in runs:
        fired = parse_rules_fired(run["rules_fired"])
        baseline_positive = bool(fired & BASELINE_POSITIVE_RULES)
        combined_positive = bool(fired & COMBINED_POSITIVE_RULES)

        baseline_class = metrics.classify_run(run["expected_class"], run["validity"], baseline_positive)
        combined_class = metrics.classify_run(run["expected_class"], run["validity"], combined_positive)

        tallies["baseline"][baseline_class] += 1
        tallies["combined"][combined_class] += 1

        scored.append({**run, "baseline_classification": baseline_class, "combined_classification": combined_class})

    with open(output_csv, "w", newline="") as fh:
        fieldnames = list(scored[0].keys())
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(scored)

    for view in ("baseline", "combined"):
        t = tallies[view]
        m = metrics.compute_metrics(tp=t["TP"], fp=t["FP"], fn=t["FN"], tn=t["TN"])
        print(f"\n=== {view} ===")
        print(f"TP={t['TP']} FP={t['FP']} FN={t['FN']} TN={t['TN']} INVALID={t['INVALID']}")
        print(f"precision={m['precision']} recall={m['recall']} f1={m['f1']} "
              f"fpr={m['false_positive_rate']} n={m['sample_size']}")

    print(f"\nWrote {len(scored)} scored rows to {output_csv}")


if __name__ == "__main__":
    main()
