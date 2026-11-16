#!/usr/bin/env bash
# Start one `kubectl logs -f` tail per Falco pod, each to its own raw JSONL file
# (no --prefix, so each file stays pure JSONL; the pod/node identity is the filename,
# not an in-line prefix string that would need separate parsing).
#
# IMPORTANT: always passes --since-time=<now> so a (re)start of this collector never
# replays each pod's buffered history. Without it, restarting the collector mid-session
# re-prints every earlier event into the new file, double-counting any run whose window
# is covered by both the old and the new file (found the hard way during Phase 2 — see
# docs/progress_az.md).
#
# Usage: collect_falco_logs.sh <output_dir>
# Prints the 3 background PIDs on stdout (one per line) so the caller can stop them later
# with `kill <pid> <pid> <pid>`.
set -euo pipefail

OUT_DIR="$1"
mkdir -p "${OUT_DIR}"

NS="falco"
SINCE_TIME="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
PODS=$(kubectl -n "${NS}" get pods -l app.kubernetes.io/name=falco -o jsonpath='{range .items[*]}{.metadata.name}{" "}{.spec.nodeName}{"\n"}{end}')

if [ -z "${PODS}" ]; then
  echo "No Falco pods found in namespace ${NS}" >&2
  exit 1
fi

while read -r POD NODE; do
  [ -z "${POD}" ] && continue
  kubectl -n "${NS}" logs "${POD}" -c falco -f --timestamps --since-time="${SINCE_TIME}" > "${OUT_DIR}/${NODE}.jsonl" 2>&1 &
  echo "$!"
done <<< "${PODS}"
