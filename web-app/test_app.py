"""Regression checks for application evidence; real MySQL is tested by the smoke runner."""
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from app import app


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "app.jsonl"
        self.env = patch.dict(os.environ, {"APP_LOG": str(self.path)})
        self.env.start()
        self.client = app.test_client()

    def tearDown(self):
        self.env.stop()
        self.tmp.cleanup()

    def query_result(self, target, observed, reference, method="GET", data=None):
        connection = MagicMock()
        cursor = connection.cursor.return_value.__enter__.return_value
        cursor.fetchall.side_effect = [observed, reference]
        with patch("app.pymysql.connect", return_value=connection):
            response = self.client.open(target, method=method, data=data,
                                        headers={"X-Lab-Case-ID": "unit-case"})
        record = json.loads(self.path.read_text(encoding="utf-8"))
        return response, record, cursor

    def test_benign_wildcard_is_not_an_injection_effect(self):
        rows = [{"id": 1, "username": "alice"}, {"id": 2, "username": "bob"}]
        response, record, cursor = self.query_result("/search?q=%25", rows, rows)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["count"], 2)
        self.assertFalse(record["semantic_effect"])
        self.assertEqual(cursor.execute.call_args.args,
                         ("SELECT id, username FROM users WHERE username LIKE %s", ("%%%",)))

    def test_expanded_product_query_has_correlated_evidence(self):
        one = [{"id": 1, "username": "alice"}]
        two = one + [{"id": 2, "username": "bob"}]
        response, record, _ = self.query_result("/product?id=1+OR+1%3D1", two, one)
        self.assertTrue(record["semantic_effect"])
        self.assertEqual(record["reference_row_ids"], [1])
        self.assertEqual(record["row_ids"], [1, 2])
        self.assertEqual(record["case_id"], response.headers["X-Lab-Case-ID"])
        self.assertEqual(record["raw_target"], "/product?id=1+OR+1%3D1")

    def test_duplicate_parameters_are_retained_but_handler_uses_first(self):
        row = [{"id": 1, "username": "alice"}]
        _, record, cursor = self.query_result("/product?id=1&id=2", row, row)
        self.assertEqual(record["parsed_pairs"], [["id", "1"], ["id", "2"]])
        self.assertEqual(cursor.execute.call_args.args[1], ("1",))

    def test_login_bypass_and_form_bytes_are_recorded(self):
        response, record, _ = self.query_result("/login", [{"id": 1, "username": "alice"}], [],
            method="POST", data={"username": "' OR 1=1 -- ", "password": "wrong"})
        self.assertTrue(response.json["success"])
        self.assertTrue(record["semantic_effect"])
        self.assertIn("password=wrong", record["raw_body"])

    def test_database_failure_is_an_error_not_an_effect(self):
        with patch("app.pymysql.connect", side_effect=RuntimeError("unit database unavailable")):
            response = self.client.get("/product?id=1")
            health = self.client.get("/healthz")
        record = json.loads(self.path.read_text(encoding="utf-8"))
        self.assertEqual(response.status_code, 200)  # Preserve the team's existing response API.
        self.assertIn("db_error", response.json)
        self.assertFalse(record["semantic_effect"])
        self.assertIsNotNone(record["sql_error"])
        self.assertEqual(health.status_code, 503)


if __name__ == "__main__":
    unittest.main()
