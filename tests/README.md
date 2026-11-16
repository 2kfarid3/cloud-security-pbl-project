# Test Matrix (Category 1)

`test_matrix.csv` is the pre-registered ground truth for every case used to evaluate the baseline and (later) improved Falco rules. It is written **before** any rule is changed, per the project brief's requirement that ground truth come from scenario design and intent, not be read back out of what a rule happens to fire.

## Columns

`case_id, family, description, expected_class, rationale, target, preconditions, command_or_script, expected_signal, split`

- `expected_class`: `benign` or `malicious` — judged from what the action actually is and its stated intent, never from whether a current rule happens to match it.
- `expected_signal`: the specific prediction being tested (which rule should/shouldn't fire). This is a hypothesis to be confirmed or refuted by execution, not a guarantee.
- `split`: `development` or `holdout`.

## Families

- `baseline_replay` — the original 4 scripts, re-included here so Phase 5 scores everything through one harness instead of citing Phase 2's numbers separately.
- `hard_normal` — legitimate activity designed to look similar to an attack case, probing for false positives.
- `attack_variant` — the same attack techniques as the originals, through a different filename/interpreter/tool, probing for false negatives (the core research question: do name/path-bound rules miss realistic variants?).
- `rule_robustness` — cases that probe a rule condition's matching logic directly (too loose or too narrow), independent of whether they look "normal" or "attack-like" day to day.

## Development vs. holdout

Development-split cases may be run and looked at before the improved rules in Phase 4 are finalized — that's the point of having a dev set, and several of them (`malicious_payload_other_name`, `malicious_payload_alt_interpreter`, `malicious_token_alt_tool`) exist specifically to show the baseline's gaps so Phase 4's rule design has concrete evidence to work from.

Holdout-split cases (`malicious_credential_existence_probe`, `malicious_token_decoy_path`) must **not** be run or inspected until Phase 5's final baseline-vs-improved comparison. If a rule gets tuned after seeing a holdout result, that holdout case is burned — it must be replaced with a new, still-unseen case before the result can be called an independent holdout measurement again (per the project brief's explicit rule on this).

## Execution notes

- Every `command_or_script` resolves the target pod via the same label-selector convention as `category1/*.sh` (`kubectl get pod -l app=... -o jsonpath=...`) rather than a hardcoded pod name, since pod names change across restarts/rollouts.
- These are not yet wired into an automated harness — that is Phase 4's job (a generalized version of `scripts/run_baseline_case.sh` that takes a `test_matrix.csv` row instead of one hardcoded script). Running them by hand for now is fine for development-split cases.
