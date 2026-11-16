#!/usr/bin/env bash
# tests/test_matrix.csv: malicious_payload_other_name (attack_variant, development)
# Same payload-execution technique as abnormal_3, different filename.
set -euo pipefail

NS="${NS:-pbl-security}"
POD="$(kubectl -n "${NS}" get pod -l app=frontend -o jsonpath='{.items[0].metadata.name}')"

kubectl -n "${NS}" exec -c frontend "${POD}" -- sh -c '
  cat >/tmp/update-check.sh <<EOF
#!/bin/sh
id
uname -a
echo reverse-shell-simulation-no-network
EOF
  chmod +x /tmp/update-check.sh
  sh /tmp/update-check.sh
  sleep 1
  rm -f /tmp/update-check.sh
'
