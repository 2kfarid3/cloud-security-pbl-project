#!/usr/bin/env python3
"""Join a run manifest (from run_baseline_case.sh) with raw per-pod Falco JSONL logs
and produce a run-level CSV: one row per case execution, with both the raw alert count
(as every Falco pod wrote it) and a deduplicated count (collapsing the cross-node
duplicate echoes documented in docs/baseline_analysis.md, keyed on
(rule, container.id, evt.time)). Only alerts tagged "pbl" are considered —
unrelated stock-Falco background noise is intentionally excluded here.

Usage: parse_falco_events.py <manifest_csv> <raw_log_dir> <output_csv>
"""
import csv
import glob
import json
import sys
from datetime import datetime, timedelta


def parse_time(s: str) -> datetime:
    s = s.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    # Python's fromisoformat wants at most 6 fractional digits.
    if "." in s:
        head, rest = s.split(".", 1)
        frac, tz = rest[:6], rest[6:]
        s = f"{head}.{frac}{tz}" if tz else f"{head}.{frac}+00:00"
    return datetime.fromisoformat(s)


DEDUP_WINDOW = timedelta(milliseconds=50)


def dedup_count(group_events):
    """Collapse cross-node echoes of the *same* underlying syscall into one.

    Empirically (see docs/baseline_analysis.md), when one real action is visible to
    more than one Falco pod (an unscoped rule condition), each pod's eBPF probe logs
    its own independent nanosecond-precision timestamp for it, so exact-time equality
    does not catch the duplicate — but the duplicates always come from *different*
    hostnames within a few microseconds of each other. Two events from the *same*
    hostname are never merged, even if they are close in time, because on a single
    node that pattern instead means two genuinely separate real actions executed back
    to back (e.g. two separate file writes a few dozen microseconds apart).

    This is a heuristic, not a formal proof: a true coincidence (two distinct real
    actions landing within the same 50ms window from different hosts) would be
    under-counted. For this lab's traffic volume that is acceptable; it should be
    revisited if cases ever run concurrently.
    """
    events = sorted(group_events, key=lambda e: e["_time"])
    clusters = []  # each: {"start": datetime, "hostnames": set()}
    for e in events:
        host = e.get("hostname")
        placed = False
        for cluster in clusters:
            if e["_time"] - cluster["start"] <= DEDUP_WINDOW and host not in cluster["hostnames"]:
                cluster["hostnames"].add(host)
                placed = True
                break
        if not placed:
            clusters.append({"start": e["_time"], "hostnames": {host}})
    return len(clusters)


def load_events(raw_log_dir: str):
    events = []
    for path in sorted(glob.glob(f"{raw_log_dir}/*.jsonl")):
        with open(path, "r", errors="replace") as fh:
            for line in fh:
                idx = line.find("{")
                if idx == -1:
                    continue
                try:
                    obj = json.loads(line[idx:])
                except json.JSONDecodeError:
                    continue
                tags = obj.get("tags", [])
                if "pbl" not in tags:
                    continue
                try:
                    obj["_time"] = parse_time(obj["time"])
                except (KeyError, ValueError):
                    continue
                events.append(obj)
    return events


# A generous "catch delayed alerts" trailing buffer can never bleed into the next
# case's events when two runs are scheduled close together. Without the cap in
# run_windows() below, a buffer longer than the gap between runs double-counts:
# alerts belonging to run N+1 would also get attributed to run N's window.
TRAIL_BUFFER = timedelta(seconds=9)
EPSILON = timedelta(milliseconds=100)


def run_windows(runs):
    """Given manifest rows (each with start_utc/end_utc strings), return a parallel
    list of (start, end) datetime windows, each capped at the next run's start time.
    `runs` must already be sorted by start time."""
    windows = []
    for i, run in enumerate(runs):
        start = parse_time(run["start_utc"])
        end = parse_time(run["end_utc"]) + TRAIL_BUFFER
        if i + 1 < len(runs):
            next_start = parse_time(runs[i + 1]["start_utc"])
            end = min(end, next_start - EPSILON)
        windows.append((start, end))
    return windows


def evaluate_run(events, start, end):
    """Return (raw_count, deduped_count, rule_counts) for the events whose _time
    falls within [start, end], grouped and deduplicated per (rule, container.id)."""
    window = [e for e in events if start <= e["_time"] <= end]

    raw_count = len(window)
    groups = {}
    for e in window:
        of = e.get("output_fields", {})
        key = (e.get("rule"), of.get("container.id"))
        groups.setdefault(key, []).append(e)

    rule_counts = {}
    for (rule, _container_id), group_events in groups.items():
        rule_counts[rule] = rule_counts.get(rule, 0) + dedup_count(group_events)

    return raw_count, sum(rule_counts.values()), rule_counts


def main():
    manifest_csv, raw_log_dir, output_csv = sys.argv[1], sys.argv[2], sys.argv[3]
    events = load_events(raw_log_dir)

    with open(manifest_csv, newline="") as fh:
        runs = list(csv.DictReader(fh))
    runs.sort(key=lambda r: parse_time(r["start_utc"]))
    windows = run_windows(runs)

    rows = []
    for run, (start, end) in zip(runs, windows):
        raw_count, deduped_count, rule_counts = evaluate_run(events, start, end)
        rows.append(
            {
                "run_id": run["run_id"],
                "case_id": run["case_id"],
                "expected_class": run["expected_class"],
                "exit_code": run["exit_code"],
                "validity": run["validity"],
                "raw_alert_count": raw_count,
                "deduped_alert_count": deduped_count,
                "rules_fired": ";".join(f"{k}={v}" for k, v in sorted(rule_counts.items())),
            }
        )

    with open(output_csv, "w", newline="") as fh:
        writer = csv.DictWriter(
            fh,
            fieldnames=[
                "run_id",
                "case_id",
                "expected_class",
                "exit_code",
                "validity",
                "raw_alert_count",
                "deduped_alert_count",
                "rules_fired",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)

    print(f"Wrote {len(rows)} rows to {output_csv}")


if __name__ == "__main__":
    main()
