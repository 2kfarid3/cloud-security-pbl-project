# Methodology

## Research question

Initial direction (title to be finalized once Phase 5's results are in): *Improving Behavior-Based Detection of Suspicious In-Pod Activity with Falco.*

Working question: how often do process/filename-bound baseline rules **miss** realistic variants of the same attack technique (different filename, different interpreter, different reading tool), and how many **false positives** do the broader conditions needed to catch those variants introduce against legitimate diagnostic activity that happens to use the same syscalls? Both sides of this tradeoff are measured with the same test matrix (`tests/test_matrix.csv`) and the same evaluator, not asserted separately.

## Ground truth

A case's `expected_class` (benign/malicious) is fixed at **design time**, from what the action actually is and its stated intent — never read back from whether a current Falco rule happens to match it. This is why `tests/test_matrix.csv` exists and is written before any rule changes: so "the rule says it's an attack" can never substitute for "we designed it as an attack." The `scenario=` label a rule's own `output:` template writes into a log line is a label the rule wrote, not independent ground truth (first observed in Phase 1 and re-confirmed through Phase 2's live runs).

Where intent cannot be fully separated from the observed syscalls (e.g. `env` run for legitimate diagnostics vs. for reconnaissance — see `tests/test_matrix.csv`'s `normal_legit_env_diagnostic` case), the case is still labeled by its *designed* intent, and the resulting rule behavior (a known, expected false positive) is reported honestly rather than redefined as a true positive after the fact.

## Development vs. holdout

Cases are split `development`/`holdout` in the test matrix. Development cases may be executed and inspected before Phase 4's improved rules are finalized, specifically to surface the baseline's gaps and inform rule design. Holdout cases are not executed or inspected until Phase 5's final scored comparison. If a rule is tuned after a holdout case's result has been seen, that case is burned for holdout purposes and must be replaced with a new, still-unseen case before a result can again be called an independent holdout measurement — this rule is stated explicitly in the project brief and is treated as load-bearing, not a formality.

## Positive/negative decision and evaluation unit

The evaluation unit is **one case execution (case × repetition)**, not one alert line. A single real action can legitimately produce more than one alert (documented cross-node duplication for container-name-unscoped rules, and the `abnormal_3` outer/inner wrapper double-count — see `docs/baseline_analysis.md`) — these must be deduplicated (`scripts/parse_falco_events.py`'s `dedup_count`) before being compared against the expected count for a case. Ten raw alert lines for one attack execution is not ten true positives.

Pre-registered per case, before execution: which specific rule(s) count as a "positive" signal for that case (`expected_signal` column). An `Informational`-priority "normal" rule firing is not itself a positive detection of an attack; an unrelated background alert (e.g. the stock `Redirect STDOUT/STDIN to Network Connection in Container` rule observed firing on the backend's own `httpd` process during Phase 2 — unrelated to any of our scenarios) is not counted as catching an attack it was never pointed at.

- **TP**: a case designed as `malicious`, run validly, produces its case's expected positive signal.
- **FN**: a case designed as `malicious`, run validly, produces no matching positive signal.
- **FP**: a case designed as `benign`, run validly, produces a positive signal.
- **TN**: a case designed as `benign`, run validly, produces no positive signal.
- **Invalid**: the target action or the observation itself could not be trusted (non-zero script exit code, Falco pod not Running/Ready at the time, collector gap) — counted separately, excluded from the TP/FP/FN/TN denominator rather than forced into one of those buckets. Phase 2's 12/12 valid runs show what "valid" looks like in practice.

## Repetitions

One smoke run first, then a target of 3 repetitions per valid case (Phase 2 precedent: `results/baseline_summary.md`, 3/3 identical and deterministic for all 4 original scenarios). This is a small-sample check for determinism, not a statistically powered sample — reported as such, never summarized as if it were a large-N study.

## Metrics (computed only when the denominator is non-zero; otherwise reported as N/A)

- Precision = TP / (TP + FP)
- Recall = TP / (TP + FN)
- F1 = 2·TP / (2·TP + FP + FN)
- False positive rate = FP / (FP + TN)

Sample size is reported alongside every metric. Repetitions of the same case, and near-duplicate variants of the same technique, are not independent real-world attack samples — they are repeated measurements of one case design, and the write-up says so rather than implying a larger effective sample.

## Status

This file will be extended once Phase 4 (rule implementation) and Phase 5 (scored baseline-vs-improved comparison) produce results to describe. As of this writing, only the baseline-replay measurement (Phase 2) and the test matrix design (Phase 3) exist.
