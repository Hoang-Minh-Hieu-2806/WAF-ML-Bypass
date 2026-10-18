"""Regression checks for semantic controls, parser policy and metric definitions."""
import json
import unittest
from pathlib import Path
from urllib.parse import parse_qsl

from run_baseline import audit_id, summarize
from test_backend import evaluate


class BaselineTests(unittest.TestCase):
    def test_corpus_has_real_effects_and_benign_controls(self):
        cases = json.loads(Path(__file__).with_name("baseline.json").read_text(encoding="utf-8"))
        self.assertEqual(len({c["id"] for c in cases}), len(cases))
        self.assertGreaterEqual(sum(c["label"] == "benign" for c in cases), 5)
        self.assertGreaterEqual(sum(c["label"] == "malicious" for c in cases), 5)
        for case in cases:
            with self.subTest(case=case["id"]):
                request = case["request"]
                status, result = evaluate(request["method"], request["path"],
                                          request.get("params", []) + request.get("form", []))
                self.assertEqual(status, 200)
                self.assertIsNone(result["sql_error"])
                self.assertEqual(result["semantic_effect"], case["label"] == "malicious")
                if case["expected"]["app"] == "all_products":
                    self.assertEqual({r[0] for r in result["rows"]}, {1, 2, 3})
                if case["expected"]["app"] == "auth_bypass":
                    self.assertEqual(result["rows"], [("student",)])

    def test_first_duplicate_wins(self):
        _, result = evaluate("GET", "/product", [("id", "1"), ("id", "1 OR 1=1")])
        self.assertEqual(result["rows"], [(1, "laptop")])
        self.assertFalse(result["semantic_effect"])

    def test_decoding_once_preserves_percent_encoding(self):
        pairs = parse_qsl("q=%2527", keep_blank_values=True)
        _, result = evaluate("GET", "/search", pairs)
        self.assertIn("%27", result["query"])
        self.assertIsNone(result["sql_error"])

    def test_detection_block_and_bypass_are_distinct(self):
        rows = [
            {"label": "malicious", "waf_decision": "blocked", "detected": True,
             "reached_app": False, "semantic_effect": False, "true_bypass": False},
            {"label": "malicious", "waf_decision": "allowed", "detected": True,
             "reached_app": True, "semantic_effect": True, "true_bypass": False},
            {"label": "malicious", "waf_decision": "allowed", "detected": False,
             "reached_app": True, "semantic_effect": True, "true_bypass": True},
            {"label": "malicious", "waf_decision": "allowed", "detected": False,
             "reached_app": True, "semantic_effect": False, "true_bypass": False},
            {"label": "benign", "waf_decision": "blocked", "detected": False,
             "reached_app": False, "semantic_effect": False, "true_bypass": False},
        ]
        result = summarize(rows)
        self.assertEqual(result["detection_rate_pct"], 50)
        self.assertEqual(result["block_rate_pct"], 25)
        self.assertEqual(result["bypass_rate_pct"], 25)
        self.assertEqual(result["fpr_blocking_pct"], 100)
        self.assertEqual(result["fnr_detection_pct"], 50)

    def test_audit_correlation_header_is_case_insensitive(self):
        self.assertEqual(audit_id({"transaction": {"request": {"headers": {
            "x-lab-case-id": "control-id"}}}}), "control-id")


if __name__ == "__main__":
    unittest.main()
