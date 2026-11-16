# Phase 4: Development-Case Results Against Baseline Rules

The 7 `development`-split cases from `tests/test_matrix.csv` were run once each (single rep — these are not yet part of the repeated-measurement evaluation; that comes in Phase 5 with the full matrix) against the **unmodified baseline** rules (`category1/falco-values.yaml`), to check each case's pre-registered `expected_signal` before designing any improved rule. Raw data: `results/phase4_dev_case_manifest.csv`, `results/phase4_dev_case_results.csv`.

| case_id | expected_class | pre-registered prediction | observed | prediction confirmed? |
|---|---|---|---|---|
| `normal_tmp_script_other_name` | benign | no alert | 0 alerts | ✅ yes |
| `normal_tmp_script_alt_interpreter` | benign | no alert | 0 alerts | ✅ yes |
| `normal_config_read_other_file` | benign | no alert (non-signal) | 0 alerts | ✅ yes |
| `normal_legit_env_diagnostic` | benign | **fires** (known FP) | 1 alert (`PBL OpenMetadata Environment Discovery`) | ✅ yes |
| `malicious_payload_other_name` | malicious | **missed** (FN) | 0 alerts | ✅ yes |
| `malicious_payload_alt_interpreter` | malicious | **missed** (FN) | 1 alert — but see caveat below | ⚠️ partially — see below |
| `malicious_token_alt_tool` | malicious | **missed** (FN) | 0 alerts | ✅ yes |

5 of 7 predictions confirmed outright. `malicious_payload_alt_interpreter` needs an honest caveat rather than a flat yes/no:

## The one surprise, and why it does not overturn the hypothesis

`malicious_payload_alt_interpreter` executes the payload with `ash` instead of `sh`, expecting the baseline's `proc.name = sh` condition to miss it. One alert was observed — but inspecting it shows it came from the **outer** `sh -c '<heredoc + chmod + ash ... + rm>'` wrapper process (the one `kubectl exec` itself runs), not from the inner `ash /tmp/openmetadata-payload.sh` process that is the actual interpreter-swap technique being tested. The wrapper's own command line still contains the literal substring `/tmp/openmetadata-payload.sh` (it's right there in the heredoc body and the call line), so `proc.args contains /tmp/openmetadata-payload.sh` matches the wrapper regardless of which interpreter runs the payload inside it. This is the same "outer shell argument coincidence" first documented in `docs/baseline_analysis.md` for the original `abnormal_3` case, now showing up again in a different case.

**What this means:** the interpreter-swap evasion itself still works — the process actually running the payload (`ash`) is never matched by name. The one alert is a side effect of how every case in this test matrix happens to be invoked (wrapped in a `sh -c '...'` from `kubectl exec`), not a property of the attack technique. If the same `ash /tmp/openmetadata-payload.sh` ran without that specific wrapping (e.g., from a shell that doesn't itself re-state the payload's path in its own argv — closer to how a real post-RCE shell would behave), there would be zero alerts. This is noted here rather than quietly treated as "rule caught it," and it's a reason the improved rule (Phase 4, next) should key off the actually-executed process (e.g. its exepath being under `/tmp/`) rather than a `contains` match on an ancestor's command line — a match that wide can accidentally paper over an evasion technique it didn't really defeat.

## What this confirms for rule design

- The baseline's `proc.name`/filename-bound conditions do have real, demonstrated false-negative exposure for `abnormal_1`-style credential access (`malicious_token_alt_tool`) and for payload execution under a different filename (`malicious_payload_other_name`). Both are legitimate Phase 4 targets for generalization.
- The `normal_legit_env_diagnostic` false positive is real and reproducible — any improved rule touching `PBL OpenMetadata Environment Discovery` should not pretend this ambiguity can be resolved by syscall pattern alone; it is reported as a limitation, not "fixed."
- The 3 `hard_normal` cases that produced 0 alerts show the current rules are not *accidentally* over-broad on these specific variants — useful negative evidence before broadening anything in Phase 4.
