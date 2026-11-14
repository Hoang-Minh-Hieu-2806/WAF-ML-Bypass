"""Small regression check for deterministic XSS augmentation and holdout."""
import csv
import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import train_xss_augmented as augmented


class XssAugmentationTests(unittest.TestCase):
    def test_sample_is_deduplicated_and_kept_out_of_http_holdout(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            train_csv, test_csv, xss_csv = (root / name for name in
                                            ("train.csv", "test.csv", "xss.csv"))
            with train_csv.open("w", newline="", encoding="utf-8") as stream:
                writer = csv.writer(stream)
                writer.writerow(["payload", "attack_type"])
                writer.writerows([("benign train", "norm"),
                                  ("sqli train", "sqli"),
                                  ("xss train", "xss")])
            with test_csv.open("w", newline="", encoding="utf-8") as stream:
                writer = csv.writer(stream)
                writer.writerow(["payload", "attack_type"])
                writer.writerows([("benign test", "norm"),
                                  ("sqli test", "sqli"),
                                  ("xss test", "xss")])
            with xss_csv.open("w", newline="", encoding="utf-8") as stream:
                writer = csv.writer(stream)
                writer.writerow(["Query", "Label"])
                for i in range(120):
                    writer.writerow([f"<script>alert({i})</script>", 1])
                    writer.writerow([f"ordinary query item {i}", 0])
                writer.writerow(["ordinary query item 0", 0])
                overlap_text = next(
                    f"lab overlap {i}" for i in range(1000)
                    if hashlib.sha256(f"lab overlap {i}".encode()).digest()[0] >= 51)
                writer.writerow([overlap_text, 0])
            with mock.patch.object(augmented, "TRAIN_QUOTAS", {"1": 20, "0": 20}), \
                 mock.patch.object(augmented, "TEST_QUOTAS", {"1": 10, "0": 10}), \
                 mock.patch.object(augmented, "TEST_BUCKET_CUTOFF", 128), \
                 mock.patch.object(augmented, "row_values", return_value=[
                     ("lab benign", "benign", "lab"),
                     ("lab sqli", "sqli", "lab"),
                     ("lab xss", "xss", "lab"),
                     (overlap_text, "benign", "lab")]):
                metrics = augmented.train_xss_augmented(
                    train_csv, test_csv, xss_csv, out_dir=root / "artifact")

        self.assertEqual(metrics["model_version"], "lr-tfidf-3cls-1.4")
        self.assertEqual(metrics["dataset"]["dedup"]["xss_source_duplicates"], 1)
        self.assertEqual(metrics["dataset"]["dedup"]["xss_source_overlaps_excluded_from_train"], 1)
        self.assertEqual(metrics["dataset"]["xss_source_training_sample_counts"],
                         {"0": 20, "1": 20})
        self.assertEqual(metrics["dataset"]["xss_source_holdout_sample_counts"],
                         {"0": 10, "1": 10})


if __name__ == "__main__":
    unittest.main()
