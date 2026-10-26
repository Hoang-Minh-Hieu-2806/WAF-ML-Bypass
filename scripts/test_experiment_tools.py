"""Regression tests for experiment accounting and reproducibility helpers."""
import importlib.util
import os
from pathlib import Path
import unittest


def _load_module(filename, name):
    saved = os.environ.pop("SSLKEYLOGFILE", None)
    try:
        spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        if saved is not None:
            os.environ["SSLKEYLOGFILE"] = saved


runner = _load_module("run_experiment.py", "run_experiment")
sweep = _load_module("sweep_thresholds.py", "sweep_thresholds")


class SummaryTests(unittest.TestCase):
    def test_incomplete_paths_are_excluded_from_their_metric_denominators(self):
        rows = [
            {"label": "malicious", "outcome": "blocked", "detected": True,
             "waf_decision": "blocked", "true_bypass": False,
             "ml_enforcement": {"outcome": "blocked", "decision": "blocked",
                                "true_bypass": False}},
            {"label": "malicious", "outcome": "transport_error", "detected": False,
             "waf_decision": None, "true_bypass": None,
             "ml_enforcement": {"outcome": "missing_evidence", "decision": None,
                                "true_bypass": None}},
        ]
        result = runner.summarize(rows)
        self.assertEqual(result["malicious_total"], 1)
        self.assertEqual(result["block_rate_pct"], 100.0)
        self.assertEqual(result["incomplete"], 1)
        self.assertEqual(result["ml_malicious_total"], 1)
        self.assertEqual(result["ml_block_rate_pct"], 100.0)
        self.assertEqual(result["ml_incomplete"], 1)

    def test_skipped_ml_has_no_ml_denominator(self):
        rows = [{"label": "benign", "outcome": "allowed", "detected": False,
                 "waf_decision": "allowed", "true_bypass": False}]
        result = runner.summarize(rows)
        self.assertEqual(result["ml_benign_total"], 0)
        self.assertIsNone(result["ml_fpr_blocking_pct"])


class MetadataTests(unittest.TestCase):
    def test_corpus_paths_follow_custom_root(self):
        directory = Path("custom-corpus-root")
        expected = directory.resolve() / "hpp" / "cases.json"
        self.assertEqual(runner.corpus_paths(directory, "hpp"), [expected])


class SweepTests(unittest.TestCase):
    def test_f1_is_computed_from_counts(self):
        rows = [
            {"label": "malicious", "ml": {"score": 0.9}},
            {"label": "malicious", "ml": {"score": 0.1}},
            {"label": "benign", "ml": {"score": 0.8}},
        ]
        self.assertEqual(sweep.metrics(rows, 0.5)["f1_pct"], 50.0)


if __name__ == "__main__":
    unittest.main()
