"""A failed browser replay must not close an unverified XSS case."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import verify_xss_execution as verifier


class PendingBrowserTests(unittest.TestCase):
    def test_browser_error_keeps_case_pending(self):
        with tempfile.TemporaryDirectory() as directory:
            run = Path(directory)
            row = {"case_id": "xss-1", "paranoia_level": 1, "http_status": 200,
                   "outcome": "execution_unverified", "waf_decision": "allowed"}
            pending = [{"case_id": "xss-1", "configuration": "crs_only",
                        "paranoia_level": 1}]
            (run / "results.json").write_text(json.dumps([row]), encoding="utf-8")
            (run / "pending_browser_verification.json").write_text(
                json.dumps(pending), encoding="utf-8")
            record = {**pending[0], "browser_error": "TimeoutError",
                      "execution_status": "not_executed", "reflected": False}
            with patch.object(verifier, "refresh_summary"), \
                 patch.object(verifier, "refresh_csv"):
                verifier.update_run_results([record], run)
            self.assertEqual(json.loads((run / "results.json").read_text()), [row])
            self.assertEqual(json.loads((run / "pending_browser_verification.json").read_text()), pending)

    def test_changed_http_status_does_not_replace_run_result(self):
        with tempfile.TemporaryDirectory() as directory:
            run = Path(directory)
            row = {"case_id": "xss-1", "paranoia_level": 1, "http_status": 200,
                   "outcome": "execution_unverified", "waf_decision": "allowed"}
            pending = [{"case_id": "xss-1", "configuration": "crs_only",
                        "paranoia_level": 1}]
            (run / "results.json").write_text(json.dumps([row]), encoding="utf-8")
            (run / "pending_browser_verification.json").write_text(
                json.dumps(pending), encoding="utf-8")
            record = {**pending[0], "browser_error": None, "http_status": 403,
                      "execution_status": "blocked", "reflected": False}
            with self.assertRaises(RuntimeError):
                verifier.update_run_results([record], run)
            self.assertEqual(json.loads((run / "results.json").read_text()), [row])
            self.assertEqual(json.loads((run / "pending_browser_verification.json").read_text()), pending)


if __name__ == "__main__":
    unittest.main()
