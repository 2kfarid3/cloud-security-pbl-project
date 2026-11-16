#!/usr/bin/env bash
# tests/test_matrix.csv: normal_tmp_script_alt_interpreter (hard_normal, development)
# Same benign /tmp script, executed via ash instead of sh.
set -euo pipefail

NS="${NS:-pbl-security}"
POD="$(kubectl -n "${NS}" get pod -l app=frontend -o jsonpath='{.items[0].metadata.name}')"

kubectl -n "${NS}" exec -c frontend "${POD}" -- sh -c '
  cat >/tmp/healthcheck-cron.sh <<EOF
#!/bin/sh
echo healthcheck-ok
EOF
  chmod +x /tmp/healthcheck-cron.sh
  ash /tmp/healthcheck-cron.sh
  rm -f /tmp/healthcheck-cron.sh
'
