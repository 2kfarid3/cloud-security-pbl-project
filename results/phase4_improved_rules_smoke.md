# Phase 4: Improved Rules — Deployment and Smoke Test

## Deployment

Improved rules (`rules/improved_falco_values.yaml`) deployed via:
```bash
helm upgrade --install falco falcosecurity/falco -n falco \
  --set tty=true --set falco.json_output=true --set falco.rule_matching=all \
  --values category1/falco-values.yaml --values rules/improved_falco_values.yaml \
  --wait --timeout 5m
```
Both `category1/falco-values.yaml` (baseline, untouched) and `rules/improved_falco_values.yaml` (new) are mounted together; Falco loads both as separate files from `rules.d/` and evaluates both rule sets concurrently against the same live traffic. Confirmed on all 3 Falco pods after rollout:
- `/etc/falco/rules.d/pbl_rules.yaml` (baseline): loads with the same pre-existing, unmodified schema warning (priority casing) documented since Phase 0 — not touched.
- `/etc/falco/rules.d/pbl_rules_improved.yaml`: `schema validation: ok`.
- `falco -L` lists all 6 baseline rule names plus the 2 new `PBL Improved *` rules.
- Active rule-file hashes recorded (differ per intended content change): `pbl_rules.yaml` and `pbl_rules_improved.yaml` sha256 in `docs/environment.md`'s update / this file's git history.
- Project pods (`frontend`, `backend`, `db`) stayed `Running` throughout — the upgrade only touched the `falco` DaemonSet.

## Bug found and fixed during this deployment

The first `helm upgrade` attempt used only `-f category1/falco-values.yaml -f rules/improved_falco_values.yaml`, omitting 3 `--set` flags (`tty=true`, `falco.json_output=true`, `falco.rule_matching=all`) that the original `install.sh` had passed on the command line and which are **not** recorded in any values file. Since `helm upgrade` (without `--reuse-values`) only applies exactly what is passed on that specific invocation, this silently reset `falco.json_output` to the chart's default (`false`) — Falco's alert output reverted to a human-readable text format, and the JSONL collector pipeline built in Phase 2 correctly produced zero parsed events (because `tags` field extraction found no JSON to parse), not because the rules didn't fire. Caught by noticing the raw log lines in `evidence/raw/phase4_smoke/*.jsonl` were the plain `07:21:00.9...: Warning PBL_EVENT ...` text form instead of JSON, and confirmed root cause via `helm get values falco -n falco --revision 1` vs `--revision 2`, which showed `falco.json_output: true` present in revision 1's user-supplied values and absent from revision 2's. Fixed by redeploying with the exact same `--set` flags `install.sh` originally used, alongside the two `-f` values files. Re-verified: `helm get values` now shows `json_output: true` restored, and the collector correctly parses JSON again.

**Lesson carried into the reproduction instructions:** any future Helm upgrade to this Falco release must either repeat `install.sh`'s exact `--set` flags, or use `helm upgrade --reuse-values`, or this silent regression recurs.

## Smoke test: 5 cases re-run under baseline+improved rules together

| case_id | expected_class | baseline-only result (Phase 4 dev-case run) | baseline+improved result (this smoke test) |
|---|---|---|---|
| `malicious_payload_other_name` | malicious | 0 alerts (FN) | **1** (`PBL Improved Script Execution From Tmp`) — FN fixed |
| `malicious_payload_alt_interpreter` | malicious | 1 alert (coincidental outer-wrapper match only — see `results/phase4_dev_case_findings.md`) | **2**: baseline's same coincidental wrapper match (1) **+** the improved rule now also directly catching the real `ash` process (1) |
| `malicious_token_alt_tool` | malicious | 0 alerts (FN) | **1** (`PBL Improved ServiceAccount Token Access Any Tool`) — FN fixed |
| `normal_tmp_script_other_name` | benign | 0 alerts (TN) | **1** (`PBL Improved Script Execution From Tmp`) — predicted new FP, confirmed |
| `normal_tmp_script_alt_interpreter` | benign | 0 alerts (TN) | **1** (`PBL Improved Script Execution From Tmp`) — predicted new FP, confirmed |

This is the core result of Phase 4's rule design: broadening the payload-execution rule from a specific filename/interpreter match to "any shell executing a script whose own argument path is under /tmp" **does** fix the two real false negatives it was designed to fix, and **does** introduce the two false positives predicted when designing it — the precision/recall tradeoff named in the research question, now measured rather than asserted.

**Side finding:** `PBL Improved Script Execution From Tmp` has no `container.name` restriction (deliberately, to cover both `frontend` and `backend`), so like the baseline's `PBL Normal Curl Health Check` rule, a single real match is independently observed by all 3 Falco pods due to the shared-kernel cross-node visibility documented in `docs/baseline_analysis.md` — raw alert count of 3 collapses to 1 deduplicated, consistent with that earlier finding, not a new bug.

## Not yet done

This is a single-rep smoke test to confirm the improved rules behave as designed, not the repeated, full-matrix evaluation. Phase 5 re-runs the **entire** `tests/test_matrix.csv` (development cases again, for the record, plus the still-untouched holdout cases) at 3 repetitions each, under baseline and improved rules together, and scores TP/FP/FN/TN/invalid formally.
