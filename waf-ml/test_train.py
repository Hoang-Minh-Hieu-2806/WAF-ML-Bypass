"""Regression checks for dataset generation and family-aware validation."""
import unittest
from collections import Counter

from build_dataset import benign_html_checks, benign_html_training, row_values
from train import CLASS_ORDER, family_counts, make_valid_splits


class DatasetTests(unittest.TestCase):
    def test_corpus_expands_to_three_labels_with_family_metadata(self):
        rows = row_values()
        counts = Counter(label for _, label, _ in rows)
        self.assertEqual(counts["sqli"], 147)
        self.assertEqual(counts["xss"], 57)
        self.assertEqual(counts["benign"], 223)
        self.assertEqual(len({text for text, _, _ in rows}), len(rows))
        self.assertTrue(all(label in CLASS_ORDER and family for _, label, family in rows))

    def test_html_gate_is_separate_from_html_training_samples(self):
        train_texts = {text for text, _ in benign_html_training()}
        check_texts = {text for text, _ in benign_html_checks()}
        self.assertEqual(len(check_texts), 30)
        self.assertEqual(len(train_texts), 32)
        self.assertFalse(train_texts & check_texts)

    def test_family_validation_reduces_five_to_four_without_fallback(self):
        rows = row_values()
        texts = [row[0] for row in rows]
        labels = [row[1] for row in rows]
        groups = [row[2] for row in rows]
        splits, report = make_valid_splits(texts, labels, groups)
        self.assertTrue(report["valid"], report)
        self.assertEqual(report["protocol"], "StratifiedGroupKFold(4, group=family)")
        self.assertEqual(report["fallback"], "reduced_stratified_group_4")
        self.assertFalse(report["attempts"][0]["valid"])
        self.assertEqual(report["family_count_per_class"], family_counts(labels, groups))
        self.assertTrue(all(fold["family_disjoint"] and
                            fold["validation_classes"] == CLASS_ORDER
                            for fold in report["folds"]))
        self.assertEqual(len(splits), 4)


if __name__ == "__main__":
    unittest.main()
