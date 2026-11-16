#!/usr/bin/env bash
# tests/test_matrix.csv: malicious_token_decoy_path (rule_robustness, HOLDOUT, expected_class=benign)
# Create and read a SYNTHETIC decoy file whose path merely contains the substrings
# 'kubernetes.io/serviceaccount' and ends with 'token', but is not the real mounted
# credential and holds only a placeholder marker string.
# HOLDOUT: not inspected before Phase 5's scored evaluation.
set -euo pipefail

NS="${NS:-pbl-security}"
POD="$(kubectl -n "${NS}" get pod -l app=backend -o jsonpath='{.items[0].metadata.name}')"

kubectl -n "${NS}" exec "${POD}" -- sh -c '
  mkdir -p /tmp/fake/kubernetes.io/serviceaccount
  echo not-a-real-token >/tmp/fake/kubernetes.io/serviceaccount/token
  cat /tmp/fake/kubernetes.io/serviceaccount/token >/dev/null
  rm -rf /tmp/fake
'
