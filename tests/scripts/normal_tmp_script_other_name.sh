#!/usr/bin/env bash
# tests/test_matrix.csv: normal_tmp_script_other_name (hard_normal, development)
# Benign /tmp script, same shape as abnormal_3's payload, different filename.
set -euo pipefail

NS="${NS:-pbl-security}"
POD="$(kubectl -n "${NS}" get pod -l app=frontend -o jsonpath='{.items[0].metadata.name}')"

kubectl -n "${NS}" exec -c frontend "${POD}" -- sh -c '
  cat >/tmp/healthcheck-cron.sh <<EOF
#!/bin/sh
echo healthcheck-ok
EOF
  chmod +x /tmp/healthcheck-cron.sh
  sh /tmp/healthcheck-cron.sh
  rm -f /tmp/healthcheck-cron.sh
'
