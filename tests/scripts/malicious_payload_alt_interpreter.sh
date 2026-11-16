#!/usr/bin/env bash
# tests/test_matrix.csv: malicious_payload_alt_interpreter (attack_variant, development)
# Same payload-execution technique and filename as abnormal_3, executed via ash instead of sh.
set -euo pipefail

NS="${NS:-pbl-security}"
POD="$(kubectl -n "${NS}" get pod -l app=frontend -o jsonpath='{.items[0].metadata.name}')"

kubectl -n "${NS}" exec -c frontend "${POD}" -- sh -c '
  cat >/tmp/openmetadata-payload.sh <<EOF
#!/bin/sh
id
uname -a
echo reverse-shell-simulation-no-network
EOF
  chmod +x /tmp/openmetadata-payload.sh
  ash /tmp/openmetadata-payload.sh
  sleep 1
  rm -f /tmp/openmetadata-payload.sh
'
