#!/usr/bin/env bash
# tests/test_matrix.csv: normal_config_read_other_file (hard_normal, development)
# Read a benign config file not on the baseline rule's allowlist.
set -euo pipefail

NS="${NS:-pbl-security}"
POD="$(kubectl -n "${NS}" get pod -l app=frontend -o jsonpath='{.items[0].metadata.name}')"

kubectl -n "${NS}" exec -c frontend "${POD}" -- cat /etc/resolv.conf >/dev/null
