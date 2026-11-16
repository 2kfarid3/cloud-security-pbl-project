#!/usr/bin/env python3
"""Unit tests for scripts/parse_falco_events.py and scripts/metrics.py.

Covers the cases the project brief calls out explicitly: empty log, duplicate
alert, bad JSON, mismatched time/pod, invalid run, zero denominator.

Run with: python3 -I tests/test_evaluator.py  (or: python3 -I -m unittest discover tests)
"""
import datetime
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

import metrics  # noqa: E402
import parse_falco_events as pfe  # noqa: E402


def _event(rule, container_id, hostname, iso_time, tags=("pbl",)):
    return {
        "rule": rule,
        "hostname": hostname,
        "time": iso_time,
        "tags": list(tags),
        "output_fields": {"container.id": container_id},
        "_time": pfe.parse_time(iso_time),
    }


class TestLoadEvents(unittest.TestCase):
    def test_empty_log(self):
        with tempfile.TemporaryDirectory() as d:
            open(os.path.join(d, "empty.jsonl"), "w").close()
            self.assertEqual(pfe.load_events(d), [])

    def test_empty_dir_no_files(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(pfe.load_events(d), [])

    def test_bad_json_is_skipped_not_fatal(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "bad.jsonl")
            with open(path, "w") as fh:
                fh.write("2026-01-01T00:00:00Z {not valid json at all\n")
                fh.write(
                    '2026-01-01T00:00:00Z {"rule":"X","hostname":"h","time":'
                    '"2026-01-01T00:00:00.000000000Z","tags":["pbl"],'
                    '"output_fields":{"container.id":"c1"}}\n'
                )
            events = pfe.load_events(d)
            # The malformed line must not crash the loader, and must not appear;
            # the well-formed line after it must still load.
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0]["rule"], "X")

    def test_untagged_event_excluded(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "untagged.jsonl")
            with open(path, "w") as fh:
                fh.write(
                    '{"rule":"Unrelated Stock Rule","hostname":"h","time":'
                    '"2026-01-01T00:00:00.000000000Z","tags":["container","network"],'
                    '"output_fields":{"container.id":"c1"}}\n'
                )
            self.assertEqual(pfe.load_events(d), [])


class TestDedup(unittest.TestCase):
    def test_duplicate_alert_same_rule_different_hosts_collapses_to_one(self):
        # The documented cross-node echo: same rule+container.id, nanoseconds apart,
        # three different hostnames -> one real action.
        events = [
            _event("R", "c1", "node-a", "2026-01-01T00:00:00.000000100Z"),
            _event("R", "c1", "node-b", "2026-01-01T00:00:00.000000200Z"),
            _event("R", "c1", "node-c", "2026-01-01T00:00:00.000000300Z"),
        ]
        self.assertEqual(pfe.dedup_count(events), 1)

    def test_same_host_close_in_time_stays_separate(self):
        # Two genuinely distinct real actions on the same node, milliseconds apart,
        # must NOT be merged just because they are close in time.
        events = [
            _event("R", "c1", "node-a", "2026-01-01T00:00:00.000010000Z"),
            _event("R", "c1", "node-a", "2026-01-01T00:00:00.000050000Z"),
        ]
        self.assertEqual(pfe.dedup_count(events), 2)

    def test_beyond_dedup_window_stays_separate_even_different_hosts(self):
        events = [
            _event("R", "c1", "node-a", "2026-01-01T00:00:00.000000000Z"),
            _event("R", "c1", "node-b", "2026-01-01T00:00:01.000000000Z"),  # 1s later
        ]
        self.assertEqual(pfe.dedup_count(events), 2)


class TestRunWindows(unittest.TestCase):
    def test_mismatched_time_excluded_from_run_window(self):
        """An event far outside a run's window (e.g. logged under the wrong
        pod/time due to a collector issue) must not be attributed to that run."""
        events = [
            _event("R", "c1", "node-a", "2026-01-01T00:00:05.000000000Z"),
        ]
        start = pfe.parse_time("2026-01-01T00:00:00Z")
        end = pfe.parse_time("2026-01-01T00:00:01Z")
        raw, deduped, rule_counts = pfe.evaluate_run(events, start, end)
        self.assertEqual((raw, deduped, rule_counts), (0, 0, {}))

    def test_window_capped_at_next_run_start(self):
        """A generous trailing buffer must not swallow the next run's alert."""
        runs = [
            {"start_utc": "2026-01-01T00:00:00Z", "end_utc": "2026-01-01T00:00:01Z"},
            {"start_utc": "2026-01-01T00:00:05Z", "end_utc": "2026-01-01T00:00:06Z"},
        ]
        windows = pfe.run_windows(runs)
        first_end = windows[0][1]
        second_start = windows[1][0]
        self.assertLess(first_end, second_start)


class TestClassifyRun(unittest.TestCase):
    def test_invalid_run_never_scored_as_tp_fp_fn_tn(self):
        self.assertEqual(
            metrics.classify_run("malicious", "invalid_nonzero_exit", True), "INVALID"
        )
        self.assertEqual(
            metrics.classify_run("benign", "invalid_nonzero_exit", False), "INVALID"
        )

    def test_tp_fn_fp_tn(self):
        self.assertEqual(metrics.classify_run("malicious", "valid", True), "TP")
        self.assertEqual(metrics.classify_run("malicious", "valid", False), "FN")
        self.assertEqual(metrics.classify_run("benign", "valid", True), "FP")
        self.assertEqual(metrics.classify_run("benign", "valid", False), "TN")


class TestComputeMetrics(unittest.TestCase):
    def test_zero_denominator_reports_na_not_crash(self):
        result = metrics.compute_metrics(tp=0, fp=0, fn=0, tn=0)
        self.assertEqual(result["precision"], "N/A")
        self.assertEqual(result["recall"], "N/A")
        self.assertEqual(result["f1"], "N/A")
        self.assertEqual(result["false_positive_rate"], "N/A")
        self.assertEqual(result["sample_size"], 0)

    def test_normal_case_computes_real_numbers(self):
        result = metrics.compute_metrics(tp=3, fp=1, fn=0, tn=3)
        self.assertAlmostEqual(result["precision"], 0.75)
        self.assertAlmostEqual(result["recall"], 1.0)
        self.assertAlmostEqual(result["false_positive_rate"], 0.25)
        self.assertEqual(result["sample_size"], 7)

    def test_recall_na_when_no_malicious_cases_at_all(self):
        result = metrics.compute_metrics(tp=0, fp=2, fn=0, tn=5)
        self.assertEqual(result["recall"], "N/A")
        self.assertIsInstance(result["precision"], float)


if __name__ == "__main__":
    unittest.main()
