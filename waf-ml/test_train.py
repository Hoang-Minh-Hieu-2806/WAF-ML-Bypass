"""Regression checks for dataset generation and family-aware validation."""
import unittest
from collections import Counter
import csv
import tempfile
from pathlib import Path
from unittest import mock

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

    def test_combined_external_training_deduplicates_and_excludes_lab_test_overlap(self):
        import train

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            train_path, test_path = root / "train.csv", root / "test.csv"
            for path, rows in (
                (train_path, [("payload", "attack_type"),
                              ("normal", "norm"), ("SQLi payload", "sqli"),
                              ("xss payload", "xss"), (" NORMAL ", "norm")]),
                (test_path, [("payload", "attack_type"),
                             ("lab test match", "norm"), ("benign holdout", "norm"),
                             ("sqli holdout", "sqli"), ("xss holdout", "xss")]),
            ):
                with path.open("w", newline="", encoding="utf-8") as stream:
                    csv.writer(stream).writerows(rows)
            lab_rows = [("SQLI PAYLOAD", "sqli", "lab"),
                        ("lab test match", "benign", "lab"),
                        (" LAB TEST MATCH ", "benign", "lab"),
                        ("new lab xss", "xss", "lab")]
            with mock.patch.object(train, "row_values", return_value=lab_rows):
                metrics = train.train_combined_external_dataset(
                    train_path, test_path, out_dir=root / "artifacts")

        dataset = metrics["dataset"]
        self.assertEqual(dataset["external_train_class_counts"],
                         {"benign": 2, "sqli": 1, "xss": 1})
        self.assertEqual(dataset["lab_class_counts"],
                         {"benign": 2, "sqli": 1, "xss": 1})
        self.assertEqual(dataset["dedup"]["external_train_internal_duplicates"], 1)
        self.assertEqual(dataset["dedup"]["lab_internal_duplicates"], 1)
        self.assertEqual(dataset["dedup"]["lab_rows_deduplicated_against_external_train"], 1)
        self.assertEqual(dataset["dedup"]["external_test_rows_excluded_for_lab_overlap"], 1)
        self.assertEqual(dataset["external_test_rows_used"], 3)


class EnsureModelLockTests(unittest.TestCase):
    def test_missing_artifacts_do_not_silently_train(self):
        import os
        import tempfile
        import unittest.mock as _mock

        import train

        with tempfile.TemporaryDirectory() as tmp, \
             _mock.patch.dict(os.environ, {"ML_MODEL_DIR": os.path.join(tmp, "artifacts"),
                                            "ML_FORCE_TRAIN": ""}), \
             _mock.patch.object(train, "train_and_save") as retrain:
            with self.assertRaises(FileNotFoundError):
                train.ensure_model()
            retrain.assert_not_called()

    def test_existing_artifacts_are_loaded_not_retrained(self):
        import json as _json
        import os
        import tempfile
        import unittest.mock as _mock

        import train

        with tempfile.TemporaryDirectory() as tmp:
            artifact_dir = os.path.join(tmp, "artifacts", "v1.1")
            os.makedirs(artifact_dir)
            with open(os.path.join(artifact_dir, "model.joblib"), "wb") as fh:
                fh.write(b"x")
            with open(os.path.join(artifact_dir, "metrics.json"), "w",
                      encoding="utf-8") as fh:
                _json.dump({"model_version": "locked-1.0"}, fh)
            env = {
                "ML_MODEL_DIR": os.path.join(tmp, "artifacts"),
                "ML_FORCE_TRAIN": "",
            }
            with _mock.patch.dict(os.environ, env, clear=False), \
                 _mock.patch.object(train, "train_and_save") as never_train:
                never_train.side_effect = AssertionError("must not retrain over artifacts")
                version = train.ensure_model()
            self.assertEqual(version, "locked-1.0")

    def test_force_train_replaces_existing_v11_only_when_requested(self):
        import json as _json
        import os
        import tempfile
        import unittest.mock as _mock

        import train

        with tempfile.TemporaryDirectory() as tmp:
            artifact_dir = os.path.join(tmp, "artifacts", "v1.1")
            os.makedirs(artifact_dir)
            with open(os.path.join(artifact_dir, "model.joblib"), "wb") as fh:
                fh.write(b"x")
            with open(os.path.join(artifact_dir, "metrics.json"), "w", encoding="utf-8") as fh:
                _json.dump({"model_version": "old"}, fh)
            with _mock.patch.dict(os.environ, {"ML_MODEL_DIR": os.path.dirname(artifact_dir),
                                            "ML_FORCE_TRAIN": "1"}), \
                 _mock.patch.object(train, "train_and_save",
                                    return_value={"model_version": "new"}) as retrain:
                self.assertEqual(train.ensure_model(), "new")
                retrain.assert_called_once_with(artifact_dir)

    def test_force_train_cannot_overwrite_v10(self):
        import os
        import unittest.mock as _mock

        import train

        with _mock.patch.dict(os.environ, {"ML_MODEL_DIR": "artifacts/v1.0",
                                            "ML_FORCE_TRAIN": "1"}), \
             _mock.patch.object(train, "train_and_save") as retrain:
            with self.assertRaises(ValueError):
                train.ensure_model()
            retrain.assert_not_called()


if __name__ == "__main__":
    unittest.main()
