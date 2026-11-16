# Phase 5: Scored Evaluation (Baseline vs. Baseline+Improved)

Full `tests/test_matrix.csv` (13 cases, including the 2 cases held out until now) run at 3 repetitions each (39 executions, 39/39 `valid`), against the live cluster with both rule sets deployed together (Falco Helm release revision 3). Raw data: `results/phase5_full_matrix_manifest.csv`, `results/phase5_full_matrix_results.csv`. Scoring: `results/phase5_scored_runs.csv`, produced by `scripts/evaluate_matrix.py` (which reuses `scripts/metrics.py`'s `classify_run`/`compute_metrics`, the same functions `tests/test_evaluator.py` unit-tests).

Every one of the 13 cases produced an identical result across all 3 repetitions — no flakiness in this sample.

## What counts as a positive signal

Pre-registered in `scripts/evaluate_matrix.py` (see `docs/methodology.md`): the 3 baseline Warning-priority rules (`PBL OpenMetadata Environment Discovery`, `PBL OpenMetadata ServiceAccount Token Access`, `PBL OpenMetadata Payload Execution`) form the **baseline** positive set; adding the 2 improved rules (`PBL Improved Script Execution From Tmp`, `PBL Improved ServiceAccount Token Access Any Tool`) forms the **combined** positive set. The Informational "normal" rules are never themselves a positive signal, in either view.

## Per-case classification

| case_id | expected_class | baseline-only | baseline+improved |
|---|---|---|---|
| `baseline_normal` | benign | TN | TN |
| `baseline_abnormal_1` | malicious | TP | TP |
| `baseline_abnormal_2` | malicious | TP | TP |
| `baseline_abnormal_3` | malicious | TP | TP |
| `normal_tmp_script_other_name` | benign | TN | **FP** |
| `normal_tmp_script_alt_interpreter` | benign | TN | **FP** |
| `normal_config_read_other_file` | benign | TN | TN |
| `normal_legit_env_diagnostic` | benign | **FP** | **FP** |
| `malicious_payload_other_name` | malicious | **FN** | **TP** |
| `malicious_payload_alt_interpreter` | malicious | TP (see caveat below) | TP |
| `malicious_token_alt_tool` | malicious | **FN** | **TP** |
| `malicious_credential_existence_probe` (**holdout**) | malicious | **FN** | **FN** |
| `malicious_token_decoy_path` (**holdout**) | benign | **FP** | **FP** |

**Caveat on `malicious_payload_alt_interpreter`'s baseline TP:** as documented in `results/phase4_dev_case_findings.md` and `docs/rule_rationale.md`, the baseline alert here comes from the outer wrapper shell's command line coincidentally containing the payload's path, not from detecting the actual `ash` process running it. It is scored TP here per the pre-registered positive-rule-set definition, but it is not a reliable detection of the interpreter-swap technique specifically — a realistic attacker not run through this exact `kubectl exec sh -c '...'` invocation style would not trigger it. This is exactly why the improved rule (which keys on the real executing process) is a meaningful change here even though the headline classification doesn't move for this one case.

## Confusion matrices and metrics

| | TP | FP | FN | TN | Precision | Recall | F1 | False Positive Rate |
|---|---|---|---|---|---|---|---|---|
| **Baseline only** | 12 | 6 | 9 | 12 | 0.667 | 0.571 | 0.615 | 0.333 |
| **Baseline + Improved** | 18 | 12 | 3 | 6 | 0.600 | 0.857 | 0.706 | 0.667 |

(n = 39 runs per view; 13 distinct case designs × 3 repetitions — see "Sample size" caveat below.)

## What changed, stated plainly

- **Recall improved substantially** (0.571 → 0.857): both confirmed false negatives from Phase 4 (`malicious_payload_other_name`, `malicious_token_alt_tool`) are now caught. F1 improved overall (0.615 → 0.706).
- **False positive rate got worse, not better** (0.333 → 0.667), and **precision dropped slightly** (0.667 → 0.600). This is not spun as an incidental cost — it is the direct, measured answer to this project's research question: broadening a rule to close a false-negative gap introduced new false positives on legitimate-looking variants (`normal_tmp_script_other_name`, `normal_tmp_script_alt_interpreter`), exactly as predicted when the rule was designed (`rule_rationale.md`).
- **The held-out `malicious_token_decoy_path` case revealed something not previously flagged as a baseline weakness**: the path-substring match (`fd.name contains kubernetes.io/serviceaccount and fd.name endswith token`) is shared, unmodified, by *both* the baseline and the improved token rule, and *both* false-positive on a synthetic decoy file that merely resembles the real mount path. This was a real blind spot in the original rule design, surfaced correctly by holding the case out until this phase rather than hand-tuning against it earlier.
- **The held-out `malicious_credential_existence_probe` case confirms a known, deliberately-left-open gap**: neither rule set has any condition for the existence-check-only reconnaissance step. This was already documented as an intentional, honestly-reported coverage gap (not a bug) back in Phase 1/4 — the holdout result doesn't change that conclusion, it independently confirms it without having been tuned against.

## Sample size and repetition caveat

n=39 is 13 distinct case designs measured 3 times each, not 39 independent real-world attack instances. Repeated executions of the same script are a determinism check (and all 13 were perfectly deterministic here), not additional statistical power. The headline metrics above should be read as "13 designed scenarios, scored," not as a large-sample estimate of real-world detection rates. `docs/methodology.md` states this same caveat for the metric formulas in general.

## Limitations this evaluation does not resolve

- Small, fixed testbed; all cases simulate already-landed post-compromise behavior, not the original OpenMetadata RCE itself.
- Both rule sets still cannot distinguish intent from syscalls alone (`normal_legit_env_diagnostic` remains an unavoidable FP in both views).
- The token-path over-broad-match weakness found here (`malicious_token_decoy_path`) is now known but not fixed in this phase — fixing it was out of scope for Phase 4's rule design (which deliberately left the path condition untouched so this holdout case would remain meaningful) and is named here as a candidate for a future iteration, not retrofitted into `rules/improved_falco_values.yaml` after seeing this result.
- This is not a claim that either rule set "catches all attacks" — `malicious_credential_existence_probe`'s confirmed FN is direct evidence against any such claim.
