#!/usr/bin/env bash
# tests/test_matrix.csv: malicious_token_alt_tool (attack_variant, development)
# Same credential-access target as abnormal_2, read with `head` instead of `cat`.
set -euo pipefail

NS="${NS:-pbl-security}"
POD="$(kubectl -n "${NS}" get pod -l app=backend -o jsonpath='{.items[0].metadata.name}')"
TOKEN="/var/run/secrets/kubernetes.io/serviceaccount/token"

kubectl -n "${NS}" exec "${POD}" -- sh -c "sleep 1; head -c 200 '${TOKEN}' >/dev/null; sleep 1"
