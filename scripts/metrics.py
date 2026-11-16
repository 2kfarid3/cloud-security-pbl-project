"""Confusion-matrix classification and metric formulas for Category 1 evaluation.

See docs/methodology.md for the full definitions this implements: the evaluation
unit is one case execution (not one alert), invalid runs are excluded from the
denominator rather than forced into a bucket, and every metric reports "N/A"
rather than raising or silently printing 0/0 when its denominator is zero.
"""


def classify_run(expected_class: str, validity: str, positive_signal_present: bool) -> str:
    """Return one of TP/FP/FN/TN/INVALID for a single run.

    expected_class: "benign" or "malicious" (pre-registered, see tests/test_matrix.csv).
    validity: "valid" or anything else (e.g. "invalid_nonzero_exit") from the run manifest.
    positive_signal_present: whether this run's pre-registered expected_signal rule(s)
    fired at least once (already deduplicated — see scripts/parse_falco_events.py).
    """
    if validity != "valid":
        return "INVALID"
    if expected_class == "malicious":
        return "TP" if positive_signal_present else "FN"
    if expected_class == "benign":
        return "FP" if positive_signal_present else "TN"
    raise ValueError(f"unknown expected_class: {expected_class!r}")


def compute_metrics(tp: int, fp: int, fn: int, tn: int) -> dict:
    """Precision/recall/F1/false-positive-rate, each "N/A" when its denominator is 0."""

    def safe_div(numerator, denominator):
        return numerator / denominator if denominator else "N/A"

    precision = safe_div(tp, tp + fp)
    recall = safe_div(tp, tp + fn)
    fpr = safe_div(fp, fp + tn)
    f1_denominator = 2 * tp + fp + fn
    f1 = safe_div(2 * tp, f1_denominator)

    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "false_positive_rate": fpr,
        "sample_size": tp + fp + fn + tn,
    }
