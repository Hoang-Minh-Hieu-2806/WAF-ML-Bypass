import unittest

from compare_a6_baseline import collect_sqli_map, compare, coverage_errors


def row(case_id, label, outcome, *, paranoia_level=1, vuln=None):
    item = {
        "case_id": case_id,
        "paranoia_level": paranoia_level,
        "label": label,
        "outcome": outcome,
    }
    if vuln is not None:
        item["vuln"] = vuln
    return item


class A6CoverageTests(unittest.TestCase):
    def test_compares_benign_and_malicious_sql_cases(self):
        # v1.0 rows lack vuln; those baselines contain only SQLi fixtures.
        baseline = [
            row("sqli-ben-001", "benign", "allowed"),
            row("sqli-mal-001", "malicious", "blocked"),
        ]
        candidate = [
            row("sqli-ben-001", "benign", "allowed", vuln="sqli"),
            row("sqli-mal-001", "malicious", "blocked", vuln="sqli"),
            row("xss-mal-001", "malicious", "blocked", vuln="xss"),
        ]

        result = compare(baseline, candidate)

        self.assertEqual(result["shared"], 2)
        self.assertEqual(result["same_outcome"], 2)
        self.assertEqual(result["shared_labels"], {"benign": 1, "malicious": 1})
        self.assertEqual(result["candidate_cases"], 2)
        self.assertFalse(result["only_in_baseline"])
        self.assertFalse(result["only_in_candidate"])

    def test_reports_unmatched_benign_control(self):
        baseline = [
            row("sqli-ben-001", "benign", "allowed"),
            row("sqli-mal-001", "malicious", "blocked"),
        ]
        candidate = [row("sqli-mal-001", "malicious", "blocked", vuln="sqli")]

        result = compare(baseline, candidate)

        self.assertEqual(result["shared"], 1)
        self.assertEqual(result["only_in_baseline"], [("sqli-ben-001", 1)])

    def test_rejects_duplicate_case_round(self):
        duplicate = [
            row("sqli-ben-001", "benign", "allowed"),
            row("sqli-ben-001", "benign", "allowed"),
        ]
        with self.assertRaisesRegex(ValueError, "duplicate SQLi case-round"):
            collect_sqli_map(duplicate)

    def test_detects_incomplete_case_and_pl_coverage(self):
        partial = [
            row("sqli-ben-001", "benign", "allowed", paranoia_level=1),
            row("sqli-mal-001", "malicious", "blocked", paranoia_level=1),
        ]

        issues = coverage_errors(partial, "candidate", expected_cases=2)

        self.assertEqual(len(issues), 2)
        self.assertIn("candidate sqli-ben-001 has PL1; expected PL1,2,3", issues)
        self.assertIn("candidate sqli-mal-001 has PL1; expected PL1,2,3", issues)

    def test_detects_sql_label_change_even_when_outcome_matches(self):
        baseline = [row("sqli-001", "benign", "allowed")]
        candidate = [row("sqli-001", "malicious", "allowed", vuln="sqli")]

        result = compare(baseline, candidate)

        self.assertEqual(result["same_outcome"], 1)
        self.assertEqual(len(result["label_mismatches"]), 1)


if __name__ == "__main__":
    unittest.main()
