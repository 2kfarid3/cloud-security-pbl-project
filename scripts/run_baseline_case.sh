#!/usr/bin/env bash
# Run one Category 1 baseline scenario script once, as one labeled "case repetition",
# and record enough metadata for later evaluation (Phase 5) without printing secret content.
#
# Usage: run_baseline_case.sh <case_id> <expected_class> <script_path> <manifest_csv>
#
# Falco pods must already be 2/2 Running and a log collector (collect_falco_logs.sh)
# must already be tailing all 3 Falco pods before this is invoked, so no early alert is missed.
set -euo pipefail

CASE_ID="$1"
EXPECTED_CLASS="$2"
SCRIPT_PATH="$3"
MANIFEST_CSV="$4"
SETTLE_SECONDS="${SETTLE_SECONDS:-10}"

RUN_ID="${CASE_ID}_$(date -u +%Y%m%dT%H%M%S%NZ)"
START_UTC="$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)"

set +e
OUT="$(bash "${SCRIPT_PATH}" 2>&1)"
EXIT_CODE=$?
set -e

END_UTC="$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)"

# A non-zero exit means the scenario script itself failed (e.g. pod not found) —
# the run is not a valid sample of the scenario and must not be scored as TP/FP/TN/FN.
VALIDITY="valid"
if [ "${EXIT_CODE}" -ne 0 ]; then
  VALIDITY="invalid_nonzero_exit"
fi

sleep "${SETTLE_SECONDS}"

if [ ! -f "${MANIFEST_CSV}" ]; then
  echo "run_id,case_id,expected_class,script,start_utc,end_utc,exit_code,validity" > "${MANIFEST_CSV}"
fi
echo "${RUN_ID},${CASE_ID},${EXPECTED_CLASS},${SCRIPT_PATH},${START_UTC},${END_UTC},${EXIT_CODE},${VALIDITY}" >> "${MANIFEST_CSV}"

echo "[run_baseline_case] ${RUN_ID} exit=${EXIT_CODE} validity=${VALIDITY}" >&2
# Script stdout/stderr intentionally not echoed here to avoid leaking any sensitive
# path/content into the terminal by accident; inspect manually only if debugging a failure.
if [ "${VALIDITY}" != "valid" ]; then
  echo "${OUT}" >&2
fi
