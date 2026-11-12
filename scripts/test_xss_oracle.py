import unittest

from xss_oracle import execution_observed


class ExecutionOracleTests(unittest.TestCase):
    def test_expected_title_marker_on_success_response_is_execution(self):
        self.assertTrue(execution_observed(200, "XSS-RAN", "XSS-RAN", []))

    def test_generic_title_change_is_not_execution_without_marker(self):
        self.assertFalse(execution_observed(200, "Welcome", "", []))

    def test_dialog_on_success_response_is_execution(self):
        self.assertTrue(execution_observed(200, "Welcome", None, ["alert"]))

    def test_blocked_response_cannot_be_execution_evidence(self):
        self.assertFalse(execution_observed(403, "403 Forbidden", None, []))
        self.assertFalse(execution_observed(403, "XSS-RAN", "XSS-RAN", ["alert"]))


if __name__ == "__main__":
    unittest.main()
