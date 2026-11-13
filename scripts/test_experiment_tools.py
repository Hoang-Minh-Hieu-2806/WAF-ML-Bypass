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
compare = _load_module("compare_a6_baseline.py", "compare_a6_baseline")


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

    def test_v1_and_v2_are_normalized_without_losing_ordered_pairs(self):
        cases = runner.load_corpus(runner.DEFAULT_CORPUS)
        self.assertEqual(len(cases), 37)
        self.assertEqual(sum(case["vuln"] == "xss" for case in cases), 10)
        hpp = next(case for case in cases if case["id"] == "xss-hpp-mal-001")
        self.assertEqual(hpp["schema_version"], 2)
        self.assertEqual(hpp["_wire_request"]["params"][0][0], "text")
        self.assertEqual(len(hpp["_wire_request"]["params"]), 2)
        legacy = next(case for case in cases if case["id"] == "hpp-mal-001")
        self.assertEqual(legacy["schema_version"], 1)
        self.assertEqual(legacy["vuln"], "sqli")

    def test_corpus_path_allowlist_rejects_traversal(self):
        with self.assertRaises(RuntimeError):
            runner.corpus_paths(runner.DEFAULT_CORPUS, "../logs")


class XssMetricTests(unittest.TestCase):
    def test_unverified_xss_is_pending_and_excluded_from_metrics(self):
        rows = [{"vuln": "xss", "label": "malicious", "outcome": "execution_unverified",
                 "waf_decision": "allowed", "true_bypass": False}]
        summary = runner.summarize(rows)
        self.assertEqual(summary["malicious_total"], 0)
        self.assertEqual(summary["execution_unverified"], 1)
        self.assertEqual(summary["by_vuln"]["xss"]["malicious_total"], 0)

    def test_verified_xss_bypass_is_counted_per_vuln(self):
        rows = [
            {"vuln": "xss", "label": "malicious", "outcome": "true_bypass_xss",
             "waf_decision": "allowed", "detected": False, "true_bypass": True,
             "true_bypass_xss": True},
            {"vuln": "sqli", "label": "malicious", "outcome": "true_bypass",
             "waf_decision": "allowed", "detected": False, "true_bypass": True,
             "true_bypass_xss": False},
        ]
        summary = runner.summarize(rows)
        self.assertEqual(summary["true_bypasses_xss"], 1)
        self.assertEqual(summary["true_bypasses"], 2)
        self.assertEqual(summary["by_vuln"]["xss"]["true_bypasses_xss"], 1)

    def test_rule_family_mapping_uses_real_rule_id_prefixes(self):
        self.assertEqual(runner.rule_families(["941100", "949110", "920350", "999999"]),
                         ["anomaly-gate", "other:999999", "protocol-transport", "xss-rule"])

    def test_true_bypass_requires_matching_waf_and_browser_evidence(self):
        self.assertTrue(runner.is_true_bypass_xss(
            "malicious", "allowed", False, True, "executed"))
        self.assertFalse(runner.is_true_bypass_xss(
            "malicious", "allowed", False, True, "execution_unverified"))
        self.assertFalse(runner.is_true_bypass_xss(
            "malicious", "allowed", True, True, "executed"))

    def test_http_reflection_requires_escaped_control_to_differ(self):
        payload = "<script>marker</script>"
        self.assertTrue(runner.xss_http_oracle(f"<div>{payload}</div>", "&lt;script&gt;", payload))
        self.assertFalse(runner.xss_http_oracle(f"<div>{payload}</div>",
                                                f"<div>{payload}</div>", payload))
        valid, evidence = runner.control_check_xss(
            {"status": 200, "body": f"<div>{payload}</div>"},
            {"status": 200, "body": "&lt;script&gt;marker&lt;/script&gt;"},
            payload, "executed")
        self.assertTrue(valid)
        self.assertEqual(evidence["execution_status"], "execution_unverified")

    def test_attack_sum_evidence_fields_are_available_for_three_class_proxy(self):
        # X4 supplies these fields; X3 must preserve them in the ML enforcement result.
        record = {"label": "benign", "scores": {"benign": 0.48, "sqli": 0.27, "xss": 0.25},
                  "attack_score": 0.52, "threshold": 0.5, "decision": "blocked"}
        result = runner.ml_evidence_fields(record)
        self.assertEqual(result["attack_score"], 0.52)
        self.assertEqual(result["scores"]["sqli"] + result["scores"]["xss"], 0.52)
        self.assertEqual(result["threshold"], 0.5)


class CompareA6Tests(unittest.TestCase):
    def test_hybrid_flip_from_ml_polarity_is_explained(self):
        baseline = [{"case_id": "hpp-mal-001", "paranoia_level": 1, "vuln": "sqli",
                     "label": "malicious", "outcome": "blocked",
                     "blocking_layer": "ml", "ml_enforcement": {"score": 0.6}}]
        candidate = [{"case_id": "hpp-mal-001", "paranoia_level": 1, "vuln": "sqli",
                      "label": "malicious", "outcome": "allowed",
                      "blocking_layer": None,
                      "hybrid_ml_evidence": {"attack_score": 0.4, "scores":
                          {"benign": 0.6, "sqli": 0.3, "xss": 0.1}}}]
        result = compare.compare(baseline, candidate)
        self.assertEqual(result["same_outcome"], 0)
        flip = result["flips"][0]
        self.assertTrue(flip["threshold_policy_explains_flip"])

    def test_direct_flip_without_polarity_change_is_unexplained(self):
        baseline = [{"case_id": "cc-mal-001", "paranoia_level": 2, "vuln": "sqli",
                     "label": "malicious", "outcome": "allowed", "ml_enforcement": {"score": 0.9}}]
        candidate = [{"case_id": "cc-mal-001", "paranoia_level": 2, "vuln": "sqli",
                      "label": "malicious", "outcome": "blocked", "blocking_layer": "crs",
                      "ml_enforcement": {"attack_score": 0.9}}]
        result = compare.compare(baseline, candidate)
        flip = result["flips"][0]
        self.assertFalse(flip["threshold_policy_explains_flip"])

    def test_attack_score_derives_from_scores_map(self):
        row = {"hybrid_ml_evidence": {"scores": {"benign": 0.5, "sqli": 0.3, "xss": 0.2}}}
        self.assertEqual(compare.ml_attack_score(row), 0.5)


class SweepTests(unittest.TestCase):
    def test_f1_is_computed_from_counts(self):
        rows = [
            {"label": "malicious", "ml": {"score": 0.9}},
            {"label": "malicious", "ml": {"score": 0.1}},
            {"label": "benign", "ml": {"score": 0.8}},
        ]
        self.assertEqual(sweep.metrics(rows, 0.5)["f1_pct"], 50.0)

    def test_attack_sum_sweep_uses_attack_score_and_reports_p2(self):
        rows = [
            {"label": "malicious",
             "ml": {"scores": {"benign": 0.2, "sqli": 0.8, "xss": 0.0},
                    "attack_score": 0.8}},
            {"label": "malicious",
             "ml": {"scores": {"benign": 0.7, "sqli": 0.1, "xss": 0.2},
                    "attack_score": 0.3}},
            {"label": "benign",
             "ml": {"scores": {"benign": 0.9, "sqli": 0.05, "xss": 0.05},
                    "attack_score": 0.1}},
        ]
        p1 = sweep.metrics(rows, 0.5)
        self.assertEqual(p1["tp"], 1)
        self.assertEqual(p1["fp"], 0)
        self.assertEqual(p1["f1_pct"], 66.67)
        p2 = sweep.p2_metrics(rows)
        self.assertEqual(p2["tp"], 1)
        self.assertEqual(p2["fp"], 0)
        self.assertEqual(p2["fpr_pct"], 0.0)

    def test_legacy_single_class_rows_have_no_p2_policy(self):
        self.assertIsNone(sweep.p2_metrics([{"label": "benign", "ml": {"score": 0.9}}]))

    def test_evidence_prefers_attack_score_over_legacy_score(self):
        row = {"ml": {"score": 0.9, "attack_score": 0.3,
                      "scores": {"benign": 0.7, "sqli": 0.3, "xss": 0.0}}}
        self.assertEqual(sweep.attack_score(row), 0.3)
        self.assertFalse(sweep.max_class_policy(row))


if __name__ == "__main__":
    unittest.main()
