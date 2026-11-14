"""Train a v1.4 candidate with a bounded sample from the XSS-only source."""
import argparse
import csv
import hashlib
import json
import random
from collections import Counter
from pathlib import Path

import joblib
import numpy as np
import sklearn
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score,
                             precision_recall_fscore_support)

from build_dataset import row_values
from train import CLASS_ORDER, THRESHOLD, build_pipeline


TRAIN_QUOTAS = {"1": 8192, "0": 4096}
TEST_QUOTAS = {"1": 5000, "0": 5000}
TEST_BUCKET_CUTOFF = 51  # About 20% of SHA-256 first-byte buckets.
SEED = 20261114


def _load_http_rows(path):
    label_map = {"norm": "benign", "sqli": "sqli", "xss": "xss"}
    rows = []
    with open(path, newline="", encoding="utf-8-sig") as stream:
        reader = csv.DictReader(stream)
        if not {"payload", "attack_type"}.issubset(reader.fieldnames or []):
            raise ValueError(f"Unexpected HttpParamsDataset schema: {path}")
        for row in reader:
            label = label_map.get((row.get("attack_type") or "").strip().lower())
            text = (row.get("payload") or "").strip()
            if label and text:
                rows.append((text, label))
    if not rows or {label for _, label in rows} != set(CLASS_ORDER):
        raise ValueError(f"Expected all three classes in {path}")
    return rows


def _dedupe(rows):
    out, seen = [], set()
    for text, label in rows:
        key = text.strip().lower()
        if key and key not in seen:
            seen.add(key)
            out.append((text, label))
    return out, seen, len(rows) - len(out)


def _metric_block(model, rows):
    texts, labels = zip(*rows)
    y_true = np.asarray(labels)
    y_pred = model.predict(texts)
    probabilities = model.predict_proba(texts)
    benign = y_true == "benign"
    attack_prob = (probabilities[:, list(model.classes_).index("sqli")] +
                   probabilities[:, list(model.classes_).index("xss")])
    present_labels = [label for label in CLASS_ORDER if np.any(y_true == label)]
    precision, recall, f1, support = precision_recall_fscore_support(
        y_true, y_pred, labels=CLASS_ORDER, zero_division=0)
    return {
        "rows": len(rows),
        "class_counts": dict(Counter(labels)),
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "macro_f1": float(f1_score(y_true, y_pred, labels=present_labels,
                                    average="macro", zero_division=0)),
        "macro_f1_labels": present_labels,
        "per_class": {label: {"precision": float(precision[i]),
                              "recall": float(recall[i]), "f1": float(f1[i]),
                              "support": int(support[i])}
                      for i, label in enumerate(CLASS_ORDER)},
        "confusion_labels": CLASS_ORDER,
        "confusion_matrix": confusion_matrix(y_true, y_pred,
                                              labels=CLASS_ORDER).tolist(),
        "benign_to_sqli_fpr": float(np.mean(y_pred[benign] == "sqli")),
        "benign_to_xss_fpr": float(np.mean(y_pred[benign] == "xss")),
        "binary_attack_f1": float(f1_score(y_true != "benign",
                                             attack_prob >= THRESHOLD,
                                             zero_division=0)),
    }


def _reservoir_add(reservoirs, text, label, quotas, rng):
    quota = quotas[label]
    bucket = reservoirs[label]
    count = bucket[0] + 1
    sample = bucket[1]
    if len(sample) < quota:
        sample.append((text, "xss" if label == "1" else "benign"))
    else:
        index = rng.randrange(count)
        if index < quota:
            sample[index] = (text, "xss" if label == "1" else "benign")
    bucket[0] = count


def train_xss_augmented(train_csv, test_csv, xss_csv, corpus_root=None,
                        out_dir="artifacts/v1.4"):
    """Train on v1.3 sources plus bounded, hash-split XSS/benign samples."""
    external_rows, _, external_dups = _dedupe(_load_http_rows(train_csv))
    http_test_rows, _, _ = _dedupe(_load_http_rows(test_csv))
    raw_lab_rows = [(text, label) for text, label, _ in row_values(corpus_root)]
    raw_lab_counts = Counter(label for _, label in raw_lab_rows)
    lab_rows = raw_lab_rows
    lab_rows, lab_keys, lab_dups = _dedupe(lab_rows)
    external_keys = {text.strip().lower() for text, _ in external_rows}
    cross_dups = sum(text.strip().lower() in external_keys for text, _ in lab_rows)
    base_train = external_rows + [
        row for row in lab_rows if row[0].strip().lower() not in external_keys]
    base_train_keys = {text.strip().lower() for text, _ in base_train}
    test_excluded = sum(text.strip().lower() in lab_keys for text, _ in http_test_rows)
    http_test = [row for row in http_test_rows
                 if row[0].strip().lower() not in lab_keys]

    http_test_keys = {text.strip().lower() for text, _ in http_test}
    reservoirs = {"train": {label: [0, []] for label in ("0", "1")},
                  "test": {label: [0, []] for label in ("0", "1")}}
    seen = {}
    duplicates = conflicting_duplicates = empty_rows = bad_labels = 0
    source_label_counts = Counter()
    base_overlap_train = source_rows = 0
    source_hash = hashlib.sha256()
    rngs = {split: {label: random.Random(SEED + i)
                    for i, label in enumerate(("0", "1"))}
            for split in ("train", "test")}

    with open(xss_csv, "rb") as raw:
        for block in iter(lambda: raw.read(1024 * 1024), b""):
            source_hash.update(block)
    with open(xss_csv, newline="", encoding="utf-8-sig") as stream:
        reader = csv.DictReader(stream)
        if not {"Query", "Label"}.issubset(reader.fieldnames or []):
            raise ValueError(f"Unexpected XSS dataset schema: {xss_csv}")
        for row in reader:
            source_rows += 1
            label = (row.get("Label") or "").strip()
            text = (row.get("Query") or "").strip()
            if label not in ("0", "1"):
                bad_labels += 1
                continue
            source_label_counts[label] += 1
            if not text:
                empty_rows += 1
                continue
            key = text.lower()
            if key in seen:
                duplicates += 1
                conflicting_duplicates += seen[key] != label
                continue
            seen[key] = label
            if key in base_train_keys:
                base_overlap_train += 1
                continue
            digest = hashlib.sha256(key.encode("utf-8")).digest()
            split = "test" if digest[0] < TEST_BUCKET_CUTOFF else "train"
            if split == "test":
                quotas = TEST_QUOTAS
            else:
                if key in http_test_keys:
                    base_overlap_train += 1
                    continue
                quotas = TRAIN_QUOTAS
            _reservoir_add(reservoirs[split], text, label,
                           quotas, rngs[split][label])

    xss_train = [row for label in ("0", "1")
                 for row in reservoirs["train"][label][1]]
    xss_test = [row for label in ("0", "1")
                for row in reservoirs["test"][label][1]]
    if conflicting_duplicates:
        raise ValueError(f"XSS source has {conflicting_duplicates} duplicate payloads with conflicting labels")
    if any(len(reservoirs["train"][label][1]) < TRAIN_QUOTAS[label]
           for label in ("0", "1")):
        raise ValueError("XSS source did not provide the requested training sample quotas")
    if any(len(reservoirs["test"][label][1]) < TEST_QUOTAS[label]
           for label in ("0", "1")):
        raise ValueError("XSS source did not provide the requested holdout quotas")

    fit_rows = base_train + xss_train
    fit_rows, _, fit_dups = _dedupe(fit_rows)
    model = build_pipeline().fit([text for text, _ in fit_rows],
                                 [label for _, label in fit_rows])
    metrics = {
        "model_version": "lr-tfidf-3cls-1.4",
        "sklearn_version": sklearn.__version__,
        "dataset": {
            "sources": ["Morzeux/HttpParamsDataset", "dataset/bypass",
                        "Mendeley XSS dataset DOI 10.17632/py6cnbgdh2.2"],
            "external_train_class_counts": dict(Counter(y for _, y in external_rows)),
            "lab_class_counts": dict(raw_lab_counts),
            "lab_unique_class_counts": dict(Counter(y for _, y in lab_rows)),
            "xss_source_rows_seen": source_rows,
            "xss_source_label_counts": dict(source_label_counts),
            "xss_source_unique_nonempty_rows": len(seen),
            "xss_source_training_sample_counts": {
                label: len(reservoirs["train"][label][1]) for label in ("0", "1")},
            "xss_source_holdout_sample_counts": {
                label: len(reservoirs["test"][label][1]) for label in ("0", "1")},
            "xss_source_candidate_counts_by_split": {
                split: {label: reservoirs[split][label][0] for label in ("0", "1")}
                for split in ("train", "test")},
            "fit_class_counts": dict(Counter(y for _, y in fit_rows)),
            "fit_rows": len(fit_rows),
            "http_test_class_counts": dict(Counter(y for _, y in http_test)),
            "http_test_rows": len(http_test),
            "xss_holdout_class_counts": dict(Counter(y for _, y in xss_test)),
            "xss_holdout_rows": len(xss_test),
            "dedup": {
                "normalization": "strip + lowercase",
                "external_train_internal": external_dups,
                "lab_internal": lab_dups,
                "lab_against_external_train": cross_dups,
                "http_test_excluded_for_lab_overlap": test_excluded,
                "xss_source_duplicates": duplicates,
                "xss_source_conflicting_duplicate_labels": conflicting_duplicates,
                "xss_source_empty_payload_rows": empty_rows,
                "xss_source_bad_label_rows": bad_labels,
                "xss_source_overlaps_excluded_from_train": base_overlap_train,
                "combined_fit_duplicates_removed": fit_dups,
            },
            "sha256": {
                "httpparams_train": hashlib.sha256(Path(train_csv).read_bytes()).hexdigest(),
                "httpparams_test": hashlib.sha256(Path(test_csv).read_bytes()).hexdigest(),
                "xss_source": source_hash.hexdigest(),
            },
            "xss_source_split": {
                "method": "deterministic SHA-256 payload hash; first-byte buckets < 51/256 held out",
                "seed_for_reservoir_sampling": SEED,
                "train_quota_by_label": TRAIN_QUOTAS,
                "holdout_quota_by_label": TEST_QUOTAS,
            },
        },
        "features": "TfidfVectorizer char_wb ngram_range=(1,2), sublinear_tf=True, min_df=1",
        "model": "LogisticRegression C=2.0, max_iter=2000",
        "threshold": THRESHOLD,
        "evaluation": {
            "httpparams_external_holdout": _metric_block(model, http_test),
            "xss_source_payload_holdout": _metric_block(model, xss_test),
        },
        "evaluation_note": (
            "v1.3 training sources plus a bounded XSS-source sample. XSS source holdout is "
            "payload-level, not family-disjoint. Source payloads are safety-neutralized and "
            "lack family/source metadata; this measures text classification, not executable XSS. "
            "Candidate only; compare with v1.3 and the unchanged 37-case lab before promotion."
        ),
    }
    output = Path(out_dir)
    output.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, output / "model.joblib", compress=3)
    (output / "metrics.json").write_text(
        json.dumps(metrics, indent=2, ensure_ascii=False), encoding="utf-8")
    return metrics


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--external-train", required=True)
    parser.add_argument("--external-test", required=True)
    parser.add_argument("--xss-csv", required=True)
    parser.add_argument("--corpus-root", default=None)
    parser.add_argument("--out-dir", default="artifacts/v1.4")
    args = parser.parse_args()
    metrics = train_xss_augmented(args.external_train, args.external_test,
                                  args.xss_csv, args.corpus_root, args.out_dir)
    print(json.dumps(metrics, ensure_ascii=False))


if __name__ == "__main__":
    main()
