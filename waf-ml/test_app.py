"""Unit and live-contract tests for legacy and three-class ML-WAF models."""
import json
import os
import unittest
import urllib.error
import urllib.request
from pathlib import Path

import app as ml_app
from train import _model_dir

BASE = "http://127.0.0.1:" + os.getenv("PORT", "5001")


def _http(method, path, payload=None):
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    headers = {"Content-Type": "application/json"} if data is not None else {}
    request = urllib.request.Request(BASE + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, response.read().decode("utf-8")
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode("utf-8")


class ScoreContract(unittest.TestCase):
    def test_health_and_score_contract(self):
        status, health_text = _http("GET", "/health")
        self.assertEqual(status, 200)
        health = json.loads(health_text)
        self.assertEqual(set(health), {"status", "model_version"})
        version = health["model_version"]
        for text in ("1 OR 1=1", "laptop bag", "admin' -- #", "<script>"):
            status, body_text = _http("POST", "/score", {"text": text})
            self.assertEqual(status, 200, text)
            body = json.loads(body_text)
            self.assertEqual(body["model_version"], version)
            if version == "lr-tfidf-3cls-1.1" or version.startswith("stub-3cls"):
                self.assertEqual(set(body), {"label", "score", "model_version", "degraded"})
                self.assertIn(body["label"], {"benign", "sqli", "xss"})
                self.assertEqual(set(body["score"]), {"benign", "sqli", "xss"})
                self.assertAlmostEqual(sum(body["score"].values()), 1.0, places=4)
            else:
                self.assertEqual(set(body), {"label", "score", "model_version"})
                self.assertIn(body["label"], {"benign", "malicious"})
                self.assertGreaterEqual(body["score"], 0.0)
                self.assertLessEqual(body["score"], 1.0)

    def test_enforcement_allows_benign_and_blocks_sqli(self):
        with urllib.request.urlopen(BASE + "/search?q=laptop", timeout=10) as response:
            self.assertEqual(response.status, 200)
            self.assertEqual(response.headers["X-ML-Decision"], "allowed")
        with self.assertRaises(urllib.error.HTTPError) as blocked:
            urllib.request.urlopen(BASE + "/product?id=1%20OR%201%3D1", timeout=10)
        self.assertEqual(blocked.exception.code, 403)
        self.assertEqual(blocked.exception.headers["X-ML-Decision"], "blocked")


class PredictionAndPolicyTests(unittest.TestCase):
    def test_loaded_model_has_supported_class_schema(self):
        if ml_app._pipeline is None:
            self.skipTest("no local artifact loaded in this test process")
        classes = set(ml_app._pipeline.classes_)
        self.assertIn(classes, ({"benign", "malicious"}, {"benign", "sqli", "xss"}))
        self.assertEqual(ml_app._legacy_binary, classes == {"benign", "malicious"})

    def test_multiclass_attack_sum_policy(self):
        scores = {"benign": 0.48, "sqli": 0.27, "xss": 0.25}
        self.assertEqual(max(scores, key=scores.get), "benign")
        self.assertAlmostEqual(ml_app._attack_score(scores), 0.52)
        self.assertTrue(ml_app._decision("benign", scores))
        self.assertFalse(ml_app._decision("benign", {"benign": 0.51,
                                                       "sqli": 0.25, "xss": 0.24}))

    def test_legacy_binary_threshold_is_preserved(self):
        self.assertTrue(ml_app._decision("malicious", 0.5))
        self.assertFalse(ml_app._decision("benign", 0.499))

    def test_model_paths_are_separate_and_selectable(self):
        previous = os.environ.get("ML_MODEL_DIR")
        try:
            os.environ["ML_MODEL_DIR"] = "artifacts/v1.0"
            self.assertEqual(_model_dir(), Path("artifacts/v1.1"))
            os.environ["ML_MODEL_DIR"] = "artifacts/v1.1"
            self.assertEqual(_model_dir(), Path("artifacts/v1.1"))
        finally:
            if previous is None:
                os.environ.pop("ML_MODEL_DIR", None)
            else:
                os.environ["ML_MODEL_DIR"] = previous

    def test_three_class_fallback_labels_xss_and_sql(self):
        old_pipeline = ml_app._pipeline
        old_legacy = ml_app._legacy_binary
        try:
            ml_app._pipeline = None
            ml_app._legacy_binary = False
            xss_label, xss_scores = ml_app._predict("<script>alert(1)</script>")
            sql_label, sql_scores = ml_app._predict("1 UNION SELECT name")
            benign_label, benign_scores = ml_app._predict("price list laptop")
            self.assertEqual(xss_label, "xss")
            self.assertEqual(sql_label, "sqli")
            self.assertEqual(benign_label, "benign")
            self.assertTrue(all(abs(sum(scores.values()) - 1.0) < 1e-9
                                for scores in (xss_scores, sql_scores, benign_scores)))
        finally:
            ml_app._pipeline = old_pipeline
            ml_app._legacy_binary = old_legacy

    def test_score_text_preserves_duplicate_values_and_body(self):
        text = ml_app._score_text(b"id=1+OR+1%3D1&id=2",
                                  b"username=alice&password=lab-only",
                                  "application/x-www-form-urlencoded")
        self.assertEqual(text, "1 OR 1=1 2 alice lab-only")
        self.assertEqual(ml_app._score_text(b"", b'{"q":"x"}', "application/json"),
                         '{"q":"x"}')


if __name__ == "__main__":
    unittest.main()
