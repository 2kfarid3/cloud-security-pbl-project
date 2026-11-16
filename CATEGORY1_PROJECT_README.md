# Category 1 — Detecting In-Pod Behavior with Falco

**Student project submission** built on top of the official testbed at https://github.com/cclab-inu/Practical-Cloud-Security-PBL. This file documents the Category 1 work only. The testbed's original, generic install guide covering all three categories is unchanged at [README.md](README.md) / [README_EN.md](README_EN.md); Categories 2 and 3 are separate assignments and out of scope for this submission.

## Problem and scope

Falco matches raw kernel syscalls against declarative rules. The testbed ships 6 baseline rules written tightly around four specific attack-replay scripts. This project asks: **how often does that tight binding (exact filename, exact interpreter, exact tool) let a realistic variant of the same technique slip through, and what false-positive cost does fixing that binding introduce against legitimate activity?** Both sides are measured with one pre-registered test matrix and one evaluator — see `docs/report.md` for the full writeup.

Real-world basis: all scenarios (baseline and new) simulate post-compromise behavior from the 2024 OpenMetadata RCE campaign on Kubernetes (Microsoft Threat Intelligence's public analysis). Nothing here is a real exploit, malware, reverse shell, or credential exfiltration — only the lab-local file/process side effects such an attacker would leave behind.

## Architecture

- kind cluster, 3 nodes (Docker containers sharing **one host kernel** — this matters, see below), Cilium CNI, Falco as a DaemonSet (`modern_ebpf` driver) on every node.
- `frontend`/`backend`/`db` workloads from the original testbed (unmodified).
- Baseline Falco rules (`category1/falco-values.yaml`) — **left byte-for-byte unmodified**, frozen and hash-verified (`docs/environment.md`, `rules/baseline_falco_values.yaml`).
- Two new, additive rules (`rules/improved_falco_values.yaml`), deployed alongside the baseline, never replacing it — full rationale in `docs/rule_rationale.md`.
- A measurement harness (`scripts/`) that runs each test case, collects Falco's JSON alert stream, deduplicates known artifacts (see below), and scores TP/FP/FN/TN/invalid against a pre-registered ground truth (`tests/test_matrix.csv`).

**Key architectural finding used throughout the evaluation:** kind's 3 "nodes" share one host kernel, so every Falco pod's eBPF probe observes every container's syscalls host-wide; only the pod on the matching node can enrich the event with container/k8s metadata. A rule without a `container.name`/k8s-field condition therefore fires once per node for one real action. The evaluator deduplicates this before scoring — full detail in `docs/baseline_analysis.md`.

## Setup

Use the testbed's own installer first (see root [README_EN.md](README_EN.md) for full prerequisites/troubleshooting):

```bash
./install.sh
kubectl get nodes      # expect 3 Ready nodes
kubectl get pods -A    # expect workload, Cilium, Falco pods Running
```

Then deploy the improved rules alongside the baseline (additive; do not replace the baseline file):

```bash
helm upgrade --install falco falcosecurity/falco -n falco --version 9.2.2 \
  --set tty=true --set falco.json_output=true --set falco.rule_matching=all \
  --values category1/falco-values.yaml \
  --values rules/improved_falco_values.yaml \
  --wait --timeout 5m
```

The explicit `--set` flags above are required on every upgrade to this release — they live only on `install.sh`'s original command line, not in any values file, and a `helm upgrade -f ...` without them silently resets `falco.json_output` to `false` (a bug we hit and fixed; see `docs/report.md` §5).

## Quickstart: reproduce the measured result

```bash
# 1. Watch live alerts (optional, for manual observation)
kubectl logs -n falco -l app.kubernetes.io/name=falco -c falco --prefix --follow | grep --line-buffered PBL_EVENT

# 2. Run the full pre-registered test matrix, 3 repetitions each
#    (see tests/test_matrix.csv for the 13 case definitions)
bash scripts/run_baseline_case.sh <case_id> <expected_class> <script_path> results/my_run_manifest.csv
#    (run once per case per repetition; results/phase5_full_matrix_manifest.csv shows the exact invocations used for this submission's numbers)

# 3. Parse collected evidence into per-run alert counts
python3 scripts/parse_falco_events.py results/my_run_manifest.csv evidence/raw/<dir> results/my_run_results.csv

# 4. Score against both rule-set views (baseline-only vs. baseline+improved)
python3 scripts/evaluate_matrix.py results/my_run_results.csv results/my_scored_runs.csv
```

Unit tests for the evaluator itself (run before trusting any of the above on real evidence):

```bash
python3 -m unittest tests/test_evaluator.py -v
```

Regenerate the result charts directly from a scored results CSV (never hand-typed, so charts and report always match):

```bash
python3 scripts/make_charts.py results/phase5_full_matrix_results.csv results/charts
```

## Key measured result

n = 39 runs (13 pre-registered cases × 3 repetitions, all valid, all deterministic). Full table, per-case breakdown, and caveats: `results/phase5_evaluation.md` / `docs/report.md`.

| | TP | FP | FN | TN | Precision | Recall | F1 | False Positive Rate |
|---|---|---|---|---|---|---|---|---|
| Baseline only | 12 | 6 | 9 | 12 | 0.667 | 0.571 | 0.615 | 0.333 |
| Baseline + Improved | 18 | 12 | 3 | 6 | 0.600 | 0.857 | 0.706 | **0.667 (worse)** |

Recall and F1 improved by generalizing two filename/tool-bound rules. **False positive rate got worse, not better**, and precision dropped slightly — reported plainly, not spun, because that tradeoff is the actual answer to this project's research question, not an incidental side effect.

## Limitations (see `docs/report.md` §6 for full detail)

- Small, fixed testbed; simulates already-landed post-compromise behavior, not the original RCE itself.
- Shared host kernel causes cross-node alert duplication, handled by evaluator-side dedup, not a rule-level fix.
- Intent is not recoverable from syscalls alone (`env` run for diagnostics vs. recon is irreducibly ambiguous).
- A path-substring credential-path match is a confirmed, shared blind spot in both rule sets (found via a holdout case, not patched here).
- One reconnaissance technique (credential-path existence-checking without reading content) is an intentional, accepted coverage gap in both rule sets.
- The host's inotify-instance fix (Phase 0) is runtime-only and not persisted — see `docs/environment.md`.
- This project does **not** claim either rule set "catches all attacks."

## Repository map (Category 1 additions only)

```
docs/            environment.md, baseline_analysis.md, methodology.md, rule_rationale.md, report.md
rules/           baseline_falco_values.yaml (frozen snapshot), improved_falco_values.yaml (new)
scripts/         collect_falco_logs.sh, run_baseline_case.sh, parse_falco_events.py,
                 metrics.py, evaluate_matrix.py, make_charts.py
tests/           test_matrix.csv, README.md, scripts/*.sh (9 new scenario scripts), test_evaluator.py
results/         manifests, per-phase results CSVs, phase5_evaluation.md, charts/
presentation/    category1_falco_detection.pptx / .pdf (13 slides, speaker notes embedded)
```
