#!/usr/bin/env bash
# tests/test_matrix.csv: malicious_credential_existence_probe (attack_variant, HOLDOUT)
# Isolated reproduction of abnormal_1's credential-path existence-check loop only
# (no env / /proc/1/environ step this time) -- existence checks, not content reads.
# HOLDOUT: not inspected before Phase 5's scored evaluation.
set -euo pipefail

NS="${NS:-pbl-security}"
POD="$(kubectl -n "${NS}" get pod -l app=backend -o jsonpath='{.items[0].metadata.name}')"

kubectl -n "${NS}" exec "${POD}" -- sh -c '
  for path in /root/.aws/credentials /root/.ssh/id_rsa /root/.kube/config /etc/shadow; do
    if [ -e "$path" ]; then
      ls -l "$path" >/dev/null
    fi
  done
'
