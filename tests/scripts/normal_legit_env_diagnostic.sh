#!/usr/bin/env bash
# tests/test_matrix.csv: normal_legit_env_diagnostic (hard_normal, development)
# Legitimate diagnostic use of `env` in the backend container.
# Known, expected false positive under the baseline rule -- see docs/methodology.md.
set -euo pipefail

NS="${NS:-pbl-security}"
POD="$(kubectl -n "${NS}" get pod -l app=backend -o jsonpath='{.items[0].metadata.name}')"

kubectl -n "${NS}" exec "${POD}" -- sh -c 'env >/dev/null'
