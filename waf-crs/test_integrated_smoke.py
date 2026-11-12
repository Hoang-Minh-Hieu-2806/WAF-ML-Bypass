"""Failure-injection tests; synthetic records here are not experimental evidence."""
import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import run_integrated_smoke as runner


class RunLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        for path in ("docker-compose.yml", "docker/waf-crs/Dockerfile",
                     "docker/waf-crs/init-audit.sh", "docker/web-app/Dockerfile",
                     "web-app/app.py", "web-app/requirements.txt", "docker/db/init/01-schema.sql",
                     "docker/db/init/02-seed.sql", "waf-crs/run_integrated_smoke.py"):
            target = self.root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((runner.ROOT / path).read_bytes())
        case = {"id": "UNIT-BENIGN", "technique": "unit-fixture", "label": "benign",
                "request": {"method": "GET", "path": "/search"}}
        (self.root / "waf-crs/integrated-smoke.json").write_text(json.dumps([case]))
        self.audits, self.apps = [], []
        self.fail_level = None
        self.fail_docker = False

    def tearDown(self):
        self.temp.cleanup()

    def command(self, args, env=None):
        if self.fail_docker and args == ["docker", "version"]:
            raise RuntimeError("Injected Docker failure")
        if "up" in args and env["CRS_PL"] == self.fail_level:
            raise RuntimeError("Injected PL startup failure")
        if "printenv" in args:
            return "On\n"
        if "port" in args:
            return "127.0.0.1:" + ("8081" if "waf-crs" in args else "8080")
        return "{}"

    def send(self, port, request, correlation):
        self.apps.append({"case_id": correlation, "sql_error": None, "semantic_effect": False})
        if port == 8081:
            self.audits.append({"transaction": {
                "request": {"headers": {"X-Lab-Case-ID": correlation}},
                "response": {"http_code": 200}, "messages": [], "producer": {"unit_fixture": True}}})
        return {"status": 200, "body": "{}", "latency_ms": 0,
                "raw_url": "http://127.0.0.1/unit-fixture", "raw_body": ""}

    def run_fixture(self, levels):
        with patch.object(runner, "ROOT", self.root), \
             patch.object(runner, "command", self.command), \
             patch.object(runner, "send", self.send), \
             patch.object(runner, "lines_since", lambda path, offset:
                          self.audits if path == runner.AUDIT else self.apps), \
             patch.object(sys, "argv", ["runner", "--levels", *levels]), \
             contextlib.redirect_stdout(io.StringIO()):
            runner.main()

    def output(self):
        out = next((self.root / "results/raw/crs-integrated").iterdir())
        return out, json.loads((out / "metadata.json").read_text())

    def test_failure_at_pl2_keeps_only_partial_results(self):
        self.fail_level = "2"
        with self.assertRaisesRegex(RuntimeError, "Injected PL"):
            self.run_fixture(["1", "2", "3"])
        out, metadata = self.output()
        self.assertEqual(metadata["status"], "failed")
        self.assertEqual(metadata["completed_levels"], [1])
        self.assertEqual(metadata["levels"], [1, 2, 3])
        self.assertTrue((out / "summary.partial.json").exists())
        for filename in ("summary.json", "results.json", "results.csv"):
            self.assertFalse((out / filename).exists())

    def test_success_publishes_complete_results_after_all_levels(self):
        self.run_fixture(["1", "2", "3"])
        out, metadata = self.output()
        self.assertEqual(metadata["status"], "complete")
        self.assertEqual(metadata["completed_levels"], [1, 2, 3])
        self.assertEqual(len(json.loads((out / "summary.json").read_text())), 3)
        self.assertTrue((out / "results.csv").exists())

    def test_docker_failure_also_records_failed_status(self):
        self.fail_docker = True
        with self.assertRaisesRegex(RuntimeError, "Injected Docker"):
            self.run_fixture(["1"])
        out, metadata = self.output()
        self.assertEqual(metadata["status"], "failed")
        self.assertEqual(metadata["completed_levels"], [])
        self.assertFalse((out / "summary.json").exists())

    def test_csv_export_failure_cannot_mark_run_complete(self):
        with patch.object(runner.csv, "DictWriter", side_effect=OSError("Injected export failure")):
            with self.assertRaisesRegex(OSError, "Injected export"):
                self.run_fixture(["1"])
        out, metadata = self.output()
        self.assertEqual(metadata["status"], "failed")
        self.assertFalse((out / "summary.json").exists())


if __name__ == "__main__":
    unittest.main()
