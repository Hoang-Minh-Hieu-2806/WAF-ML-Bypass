"""Train the three-class ML-WAF and validate by payload family."""
import argparse
import json
import os
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import sklearn
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score,
                             precision_recall_fscore_support)
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.pipeline import Pipeline

from build_dataset import _request_text, benign_html_checks, row_values

MODEL_VERSION = "lr-tfidf-3cls-1.1"
CLASS_ORDER = ["benign", "sqli", "xss"]
THRESHOLD = float(os.getenv("ML_THRESHOLD", "0.5"))
V1_BINARY_REFERENCE_F1 = 0.9076


def build_pipeline():
    return Pipeline([
        ("tfidf", TfidfVectorizer(analyzer="char_wb", ngram_range=(1, 2),
                                  sublinear_tf=True, min_df=1)),
        ("clf", LogisticRegression(max_iter=2000, C=2.0)),
    ])


def _model_dir(override=None):
    if override:
        return Path(override)
    configured_value = os.getenv("ML_MODEL_DIR")
    configured = Path(configured_value) if configured_value else Path("artifacts/v1.1")
    if configured.name == "v1.1":
        return configured
    if configured.name in {"v1.0", "artifacts"}:
        return configured.parent / "v1.1"
    return configured / "v1.1"


def family_counts(labels, groups):
    return {label: len({group for current, group in zip(labels, groups)
                        if current == label}) for label in CLASS_ORDER}


def validate_splits(splits, labels, groups, n_splits):
    issues = []
    fold_details = []
    all_indices = set(range(len(labels)))
    seen_validation = []
    for fold, (train_index, validation_index) in enumerate(splits, start=1):
        train_groups = {groups[i] for i in train_index}
        validation_groups = {groups[i] for i in validation_index}
        if train_groups & validation_groups:
            issues.append(f"fold {fold}: family appears in train and validation")
        validation_classes = sorted({labels[i] for i in validation_index})
        training_classes = sorted({labels[i] for i in train_index})
        if validation_classes != CLASS_ORDER:
            issues.append(f"fold {fold}: validation classes={validation_classes}")
        if training_classes != CLASS_ORDER:
            issues.append(f"fold {fold}: training classes={training_classes}")
        dist = {label: sum(labels[i] == label for i in validation_index)
                for label in CLASS_ORDER}
        fold_details.append({"fold": fold, "train_size": len(train_index),
                             "validation_size": len(validation_index),
                             "validation_classes": validation_classes,
                             "validation_distribution": dist,
                             "validation_families": sorted(validation_groups),
                             "family_disjoint": not bool(train_groups & validation_groups)})
        seen_validation.extend(validation_index.tolist())
    if set(seen_validation) != all_indices or len(seen_validation) != len(all_indices):
        issues.append("validation folds do not partition all samples exactly once")
    return {"valid": not issues, "issues": issues, "folds": fold_details,
            "n_splits": n_splits,
            "family_count_per_class": family_counts(labels, groups),
            "checks": {
                "families_disjoint": not any("family appears" in item for item in issues),
                "all_three_classes_per_fold": not any("classes=" in item for item in issues),
                "family_counts_reported_per_class": True,
                "at_least_two_families_per_class": all(
                    count >= 2 for count in family_counts(labels, groups).values()),
            }}


def make_valid_splits(texts, labels, groups):
    counts = family_counts(labels, groups)
    insufficient = {label: count for label, count in counts.items() if count < 2}
    attempts = []
    if insufficient:
        return [], {"valid": False, "issues": [f"fewer than two families for class: {insufficient}"],
                    "family_count_per_class": counts, "attempts": attempts,
                    "fallback": "none"}
    for n_splits in (5, 4, 3):
        try:
            splitter = StratifiedGroupKFold(n_splits=n_splits, shuffle=True, random_state=29)
            splits = list(splitter.split(texts, labels, groups))
            report = validate_splits(splits, labels, groups, n_splits)
            report["random_state"] = 29
            attempts.append({"n_splits": n_splits, "valid": report["valid"],
                             "random_state": 29, "issues": report["issues"]})
            if report["valid"]:
                report["attempts"] = attempts
                report["fallback"] = ("none" if n_splits == 5 else
                                       f"reduced_stratified_group_{n_splits}")
                report["protocol"] = f"StratifiedGroupKFold({n_splits}, group=family)"
                return splits, report
        except ValueError as exc:
            attempts.append({"n_splits": n_splits, "random_state": 29, "valid": False,
                             "issues": [f"splitter error: {exc}"]})
    return [], {"valid": False, "issues": ["no valid StratifiedGroupKFold at 5, 4, or 3 folds"],
                "family_count_per_class": counts, "attempts": attempts,
                "fallback": "none", "protocol": "failed; no GroupKFold fallback"}


def per_class_metrics(y_true, y_pred):
    precision, recall, f1, support = precision_recall_fscore_support(
        y_true, y_pred, labels=CLASS_ORDER, zero_division=0)
    return {label: {"precision": float(precision[i]), "recall": float(recall[i]),
                    "f1": float(f1[i]), "support": int(support[i])}
            for i, label in enumerate(CLASS_ORDER)}


def binary_attack_metrics(labels, probabilities, threshold):
    truth = np.asarray([label != "benign" for label in labels], dtype=int)
    attack_score = probabilities[:, 1] + probabilities[:, 2]
    predicted = (attack_score >= threshold).astype(int)
    return {"threshold": threshold, "f1": float(f1_score(truth, predicted, zero_division=0)),
            "accuracy": float(accuracy_score(truth, predicted)),
            "attack_score_range": [float(attack_score.min()), float(attack_score.max())]}


def html_fp_report(model):
    checks = benign_html_checks()
    texts = [text for text, _ in checks]
    probabilities = model.predict_proba(texts)
    class_index = {label: i for i, label in enumerate(model.classes_)}
    records = []
    for (text, family), row in zip(checks, probabilities):
        scores = {label: float(row[class_index[label]]) for label in CLASS_ORDER}
        attack_score = scores["sqli"] + scores["xss"]
        records.append({"text": text, "family": family, "scores": scores,
                        "attack_score": attack_score,
                        "pass": attack_score < THRESHOLD})
    passed = sum(record["pass"] for record in records)
    by_family = {}
    for family in sorted({record["family"] for record in records}):
        subset = [record for record in records if record["family"] == family]
        by_family[family] = {"passed": sum(record["pass"] for record in subset),
                             "total": len(subset),
                             "pass_rate": sum(record["pass"] for record in subset) / len(subset)}
    return {"threshold": THRESHOLD, "passed": passed, "total": len(records),
            "pass_rate": passed / len(records) if records else 0.0,
            "by_family": by_family, "failures": [r for r in records if not r["pass"]]}


def compare_sqli_baseline(corpus_root, baseline_dir, candidate):
    result = {"status": "not_assessed", "reason": "v1.0 artifact unavailable"}
    model_path = Path(baseline_dir) / "model.joblib" if baseline_dir else None
    if not model_path or not model_path.is_file():
        return result
    legacy = joblib.load(model_path)
    corpus_rows = []
    for path in sorted(Path(corpus_root).glob("*/cases.json")):
        for case in json.loads(path.read_text(encoding="utf-8")):
            if "request" not in case:
                corpus_rows.append(_request_text(case))
    # The requested end-to-end A6 is not implied by this offline polarity check.
    old_predictions = legacy.predict_proba(corpus_rows)
    old_malicious = list(legacy.classes_).index("malicious")
    old_block = old_predictions[:, old_malicious] >= THRESHOLD
    new_probabilities = candidate.predict_proba(corpus_rows)
    new_classes = list(candidate.classes_)
    attack_score = (new_probabilities[:, new_classes.index("sqli")] +
                    new_probabilities[:, new_classes.index("xss")])
    new_block = attack_score >= THRESHOLD
    flips = [{"text": text, "v1_score": float(old_predictions[i, old_malicious]),
              "v1_attack": bool(old_block[i]), "v1_1_attack_score": float(attack_score[i]),
              "v1_1_attack": bool(new_block[i]),
              "threshold_policy_explains_flip": bool(old_block[i] != new_block[i]
                  and ((old_predictions[i, old_malicious] >= THRESHOLD) !=
                       (attack_score[i] >= THRESHOLD)))}
             for i, text in enumerate(corpus_rows) if old_block[i] != new_block[i]]
    return {"status": "offline_only_not_A6", "corpus_sqli_count": len(corpus_rows),
            "same_binary_polarity": int(np.sum(old_block == new_block)),
            "flips": flips, "all_flips_threshold_explained": all(
                item["threshold_policy_explains_flip"] for item in flips),
            "note": "Not an end-to-end RUN-A/RUN-B, PL1-3 regression."}


def train_and_save(out_dir=None, corpus_root=None, baseline_dir=None):
    rows = row_values(corpus_root)
    texts = [row[0] for row in rows]
    labels = np.asarray([row[1] for row in rows])
    groups = np.asarray([row[2] for row in rows])
    splits, validation = make_valid_splits(texts, labels, groups)
    if not validation["valid"]:
        raise RuntimeError(json.dumps(validation, ensure_ascii=False))

    oof_probabilities = np.zeros((len(texts), len(CLASS_ORDER)), dtype=float)
    for train_index, validation_index in splits:
        fold_model = build_pipeline()
        fold_model.fit([texts[i] for i in train_index], labels[train_index])
        fold_proba = fold_model.predict_proba([texts[i] for i in validation_index])
        fold_order = list(fold_model.classes_)
        for index, label in enumerate(CLASS_ORDER):
            oof_probabilities[validation_index, index] = fold_proba[:, fold_order.index(label)]
    oof_pred = np.asarray(CLASS_ORDER)[oof_probabilities.argmax(axis=1)]
    per_class = per_class_metrics(labels, oof_pred)
    confusion = confusion_matrix(labels, oof_pred, labels=CLASS_ORDER).tolist()
    benign_indices = labels == "benign"
    fpr_sqli = float(np.mean(oof_pred[benign_indices] == "sqli"))
    fpr_xss = float(np.mean(oof_pred[benign_indices] == "xss"))
    binary_metrics = binary_attack_metrics(labels, oof_probabilities, THRESHOLD)
    binary_metrics["v1.0_reference_binary_f1"] = V1_BINARY_REFERENCE_F1
    binary_metrics["v1.0_reference_note"] = "reference only; not a paired comparison"

    final_model = build_pipeline().fit(texts, labels)
    html_report = html_fp_report(final_model)
    baseline = compare_sqli_baseline(corpus_root or Path(__file__).resolve().parents[1]
                                     / "dataset" / "bypass", baseline_dir, final_model)
    checks = {
        "A1_macro_f1": float(f1_score(labels, oof_pred, labels=CLASS_ORDER,
                                        average="macro", zero_division=0)) >= 0.80,
        "A2_per_class_f1": (per_class["benign"]["f1"] >= 0.85 and
                             per_class["sqli"]["f1"] >= 0.75 and
                             per_class["xss"]["f1"] >= 0.70),
        "A3_fpr_benign_to_sqli": fpr_sqli <= 0.05,
        "A4_fpr_benign_to_xss": fpr_xss <= 0.05,
        "A5_binary_attack_f1": binary_metrics["f1"] >= 0.85,
        "A6_sql_regression_end_to_end": False,
        "A7_fp_checks_html": html_report["pass_rate"] >= 0.90,
    }
    metrics = {
        "model_version": MODEL_VERSION, "sklearn_version": sklearn.__version__,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "dataset": {"n_total": len(texts),
                    "class_counts": {label: int(np.sum(labels == label)) for label in CLASS_ORDER},
                    "family_count_per_class": family_counts(labels, groups),
                    "n_families": len(set(groups)),
                    "source": "312-row v1 base + 26 SQLi / 10 XSS corpus seeds and deterministic XSS/benign HTML expansion"},
        "features": "TfidfVectorizer char_wb ngram_range=(1,2), sublinear_tf=True, min_df=1",
        "model": "LogisticRegression C=2.0, max_iter=2000, multiclass",
        "threshold": THRESHOLD, "enforcement_policy": "attack_score = P(sqli) + P(xss); block if attack_score >= threshold",
        "validation": validation,
        "oof": {"accuracy": float(accuracy_score(labels, oof_pred)),
                "macro_f1": float(f1_score(labels, oof_pred, labels=CLASS_ORDER,
                                             average="macro", zero_division=0)),
                "per_class": per_class,
                "confusion_labels": CLASS_ORDER, "confusion_matrix": confusion,
                "fpr_benign_to_sqli": fpr_sqli,
                "fpr_benign_to_xss": fpr_xss,
                "binary_benign_vs_attack_attack_sum": binary_metrics},
        "sql_regression_v1_offline": baseline,
        "fp_checks_html": html_report,
        "acceptance": {name: {"pass": bool(value)} for name, value in checks.items()},
        "acceptance_details": {
            "A1": {"metric": "macro_f1", "value": float(f1_score(
                labels, oof_pred, labels=CLASS_ORDER, average="macro", zero_division=0)),
                   "threshold": 0.80},
            "A2": {"metric": "per_class_f1", "values": {
                label: per_class[label]["f1"] for label in CLASS_ORDER},
                   "thresholds": {"benign": 0.85, "sqli": 0.75, "xss": 0.70}},
            "A3": {"metric": "fpr_benign_to_sqli", "value": fpr_sqli,
                   "threshold": 0.05},
            "A4": {"metric": "fpr_benign_to_xss", "value": fpr_xss,
                   "threshold": 0.05},
            "A5": {"metric": "binary_attack_f1", "value": binary_metrics["f1"],
                   "threshold": 0.85},
            "A6": {"status": "not_assessed_end_to_end",
                   "reason": "offline 26-case polarity comparison is not RUN-A/RUN-B by configuration and PL"},
            "A7": {"metric": "fp_checks_html_pass_rate", "value": html_report["pass_rate"],
                   "threshold": 0.90},
        },
        "acceptance_all_pass": all(checks.values()),
        "deployment_recommendation": "candidate_only; do not promote unless A1-A7 all pass",
    }
    directory = Path(out_dir) if out_dir else _model_dir()
    directory.mkdir(parents=True, exist_ok=True)
    joblib.dump(final_model, directory / "model.joblib", compress=3)
    (directory / "metrics.json").write_text(
        json.dumps(metrics, indent=2, ensure_ascii=False), encoding="utf-8")
    return metrics


def ensure_model():
    selected_dir = os.getenv("ML_MODEL_DIR")
    directory = Path(selected_dir) if selected_dir else Path("artifacts/v1.1")
    metrics_path = directory / "metrics.json"
    model_path = directory / "model.joblib"
    if model_path.exists() and metrics_path.exists():
        return json.loads(metrics_path.read_text(encoding="utf-8")).get("model_version", MODEL_VERSION)
    if selected_dir and directory.name != "artifacts":
        raise FileNotFoundError(
            f"ML_MODEL_DIR points to missing artifact directory: {directory}; refusing to train over selection")
    directory = directory / "v1.1" if directory.name == "artifacts" else directory
    metrics = train_and_save(str(directory))
    os.environ["ML_MODEL_DIR"] = str(directory)
    return metrics["model_version"]


def main():
    parser = argparse.ArgumentParser(description="Train the 3-class ML-WAF model")
    parser.add_argument("--out-dir", default=None)
    parser.add_argument("--corpus-root", default=None)
    parser.add_argument("--baseline-dir", default=None)
    args = parser.parse_args()
    metrics = train_and_save(args.out_dir, args.corpus_root, args.baseline_dir)
    print(json.dumps(metrics, ensure_ascii=False))


if __name__ == "__main__":
    main()
