"""T03 — unit test cho waf-ml scoring API (stdlib-only, chạy trong container).

Lệnh: docker compose exec -T waf-ml python -m unittest test_app -v
(app.py cần /app/artifacts/metrics.json; nếu thiếu model, restart container
trước để server.py tự train theo ensure_model.)

Phổ: contract /health §3 docs/interfaces.md, schema response, request không
hợp lệ (text rỗng / thiếu field), nhãn-điểm hợp lý, classes_ ổn định, và
đường fallback regex stub khi model.joblib không nạp được — như mô tả app.py.
Dùng HTTP thật tới uvicorn (localhost), không cần testclient.
"""
import os
import unittest
import urllib.error
import urllib.request

import app as ml_app

BASE = "http://127.0.0.1:" + os.getenv("PORT", "5001")


def _http(method, path, payload=None):
    data = None
    headers = {}
    if payload is not None:
        import json

        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(BASE + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, response.read().decode("utf-8")
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode("utf-8")


class ScoreContract(unittest.TestCase):
    def test_health_contract(self):
        status, body_text = _http("GET", "/health")
        self.assertEqual(status, 200)
        import json

        body = json.loads(body_text)
        self.assertEqual(set(body), {"status", "model_version"})
        self.assertEqual(body["status"], "ok")
        self.assertTrue(body["model_version"])

    def test_score_schema_and_labels(self):
        import json

        for text in ("1 OR 1=1", "laptop bag", 'admin\' -- #', "-1 UNION SELECT name"):
            status, body_text = _http("POST", "/score", {"text": text})
            self.assertEqual(status, 200, text)
            body = json.loads(body_text)
            self.assertEqual(set(body), {"label", "score", "model_version"}, text)
            self.assertIn(body["label"], ("benign", "malicious"), text)
            self.assertTrue(0.0 <= body["score"] <= 1.0, text)
            self.assertTrue(body["model_version"], text)

    def test_plain_benign_scores_low_and_sqli_is_malicious(self):
        import json

        _, body_benign = _http("POST", "/score", {"text": "màn hình laptop 450"})
        _, body_attack = _http("POST", "/score", {"text": "-1 UNION SELECT id FROM users"})
        benign, attack = json.loads(body_benign), json.loads(body_attack)
        self.assertEqual(benign["label"], "benign", benign)
        self.assertEqual(attack["label"], "malicious", attack)
        self.assertLess(benign["score"], 0.5, benign)
        self.assertGreaterEqual(attack["score"], 0.5, attack)

    def test_missing_text_field_defaults_empty(self):
        import json

        status, body_text = _http("POST", "/score", {})
        self.assertEqual(status, 200)
        self.assertIn(json.loads(body_text)["label"], ("benign", "malicious"))

    def test_empty_text_does_not_crash(self):
        import json

        status, body_text = _http("POST", "/score", {"text": ""})
        self.assertEqual(status, 200)
        self.assertIn(json.loads(body_text)["label"], ("benign", "malicious"))

    def test_enforcement_allows_benign_and_blocks_sqli(self):
        with urllib.request.urlopen(BASE + "/search?q=laptop", timeout=10) as response:
            self.assertEqual(response.status, 200)
            self.assertEqual(response.headers["X-ML-Decision"], "allowed")
        with self.assertRaises(urllib.error.HTTPError) as blocked:
            urllib.request.urlopen(BASE + "/product?id=1%20OR%201%3D1", timeout=10)
        self.assertEqual(blocked.exception.code, 403)
        self.assertEqual(blocked.exception.headers["X-ML-Decision"], "blocked")


class FallbackStub(unittest.TestCase):
    """Khi model.joblib không nạp được, _predict phải dùng regex stub — contract không đổi."""

    def test_stub_predict_when_no_pipeline(self):
        saved_pipeline = ml_app._pipeline
        try:
            ml_app._pipeline = None
            label, score = ml_app._predict("1 UNION SELECT * FROM users")
            self.assertEqual(label, "malicious")
            self.assertEqual(score, 0.9)
            label, score = ml_app._predict("just chair shopping")
            self.assertEqual(label, "benign")
            self.assertEqual(score, 0.1)
        finally:
            ml_app._pipeline = saved_pipeline

    def test_loaded_pipeline_has_stable_class_order(self):
        if ml_app._pipeline is None:
            self.skipTest("model không nạp (fallback stub) — API vẫn phải hoạt động")
        self.assertEqual(list(ml_app._pipeline.classes_), ["benign", "malicious"])


class EnforcementHelpers(unittest.TestCase):
    def test_score_text_keeps_duplicate_values_in_order(self):
        text = ml_app._score_text(
            b"id=1+OR+1%3D1&id=2",
            b"username=alice&password=lab-only",
            "application/x-www-form-urlencoded",
        )
        self.assertEqual(text, "1 OR 1=1 2 alice lab-only")

    def test_score_text_accepts_non_form_body(self):
        text = ml_app._score_text(b"", b'{"query":"1 OR 1=1"}', "application/json")
        self.assertEqual(text, '{"query":"1 OR 1=1"}')


if __name__ == "__main__":
    unittest.main()
