"""T03 — huấn luyện ML-WAF v0: TF-IDF (char n-grams) + LogisticRegression.

Chạy trong container waf-ml (server.py gọi ensure_model trước khi import app)
hoặc trên host: `python train.py` từ thư mục waf-ml/. Train/test tách theo
family (GroupKFold 5 folds) — mutation cùng template không được phép nằm
song song ở hai tập, tránh leakage làm F1 đẹp ảo.
"""
import json
import os
from datetime import datetime, timezone
from pathlib import Path

import joblib
import sklearn
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score
from sklearn.model_selection import GroupKFold, cross_val_predict
from sklearn.pipeline import Pipeline

from build_dataset import row_values

MODEL_VERSION = "lr-tfidf-1.0"


def build_pipeline():
    return Pipeline([
        ("tfidf", TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 5),
                                  sublinear_tf=True, min_df=1)),
        ("clf", LogisticRegression(max_iter=2000, C=2.0)),
    ])


def _model_dir(override=None):
    return Path(override or os.getenv("ML_MODEL_DIR", "artifacts"))


def train_and_save(out_dir=None):
    texts, labels, groups = map(list, zip(*row_values()))
    y = [1 if label == "malicious" else 0 for label in labels]
    pipe = build_pipeline()
    cv = GroupKFold(n_splits=5)
    proba = cross_val_predict(pipe, texts, y, groups=groups, cv=cv,
                              method="predict_proba")
    pred = [1 if p[1] >= 0.5 else 0 for p in proba]
    metrics = {
        "model_version": MODEL_VERSION,
        "sklearn_version": sklearn.__version__,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "split": "GroupKFold5 (group=family, chống leakage mutation)",
        "features": "TfidfVectorizer char_wb 2-5 grams, sublinear_tf",
        "model": "LogisticRegression C=2.0, max_iter=2000",
        "n_total": len(texts),
        "n_malicious": sum(1 for label in labels if label == "malicious"),
        "n_benign": sum(1 for label in labels if label == "benign"),
        "n_families": len(set(groups)),
        "accuracy": None, "precision": None, "recall": None, "f1": None,
        "fpr": None, "fnr": None, "auroc": None,
        "confusion": {}, "per_family_detection": {}, "per_family_fpr": {},
    }
    tp = sum(1 for a, b in zip(pred, y) if a == 1 and b == 1)
    fp = sum(1 for a, b in zip(pred, y) if a == 1 and b == 0)
    fn = sum(1 for a, b in zip(pred, y) if a == 0 and b == 1)
    tn = sum(1 for a, b in zip(pred, y) if a == 0 and b == 0)
    metrics["accuracy"] = round((tp + tn) / len(pred), 4)
    metrics["precision"] = round(tp / (tp + fp), 4) if tp + fp else 0.0
    metrics["recall"] = round(tp / (tp + fn), 4) if tp + fn else 0.0
    metrics["f1"] = round(2 * tp / (2 * tp + fp + fn), 4) if 2 * tp + fp + fn else 0.0
    metrics["fpr"] = round(fp / (fp + tn), 4) if fp + tn else 0.0
    metrics["fnr"] = round(fn / (fn + tp), 4) if fn + tp else 0.0
    metrics["auroc"] = round(roc_auc_score(y, [p[1] for p in proba]), 4)
    metrics["confusion"] = {"tn": tn, "fp": fp, "fn": fn, "tp": tp}

    detections = {}
    for got, want, group in zip(pred, y, groups):
        if want != 1:
            continue
        detections.setdefault(group, [0, 0])
        detections[group][0] += got
        detections[group][1] += 1
    metrics["per_family_detection"] = {
        fam: f"{ok}/{n} = {round(ok / n * 100, 1)}%" for fam, (ok, n) in detections.items()}

    # Fit lần cuối trên toàn bộ dữ liệu với nhãn dạng chữ để classes_ =
    # ["benign", "malicious"], giúp app.py tra chỉ số predict_proba dễ dàng.
    pipe.fit(texts, labels)
    directory = _model_dir(out_dir)
    directory.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipe, directory / "model.joblib", compress=3)
    (directory / "metrics.json").write_text(
        json.dumps(metrics, indent=2), encoding="utf-8")
    return metrics


def ensure_model():
    """Đặt model sẵn cho server.py; trả về model_version đang dùng."""
    directory = _model_dir()
    has_model = (directory / "model.joblib").exists()
    has_meta = (directory / "metrics.json").exists()
    if has_model and has_meta:
        meta = json.loads((directory / "metrics.json").read_text(encoding="utf-8"))
        return meta.get("model_version", MODEL_VERSION)
    metrics = train_and_save(str(directory))
    return metrics["model_version"]


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Huấn luyện ML-WAF v0 và lưu artifacts")
    parser.add_argument("--out-dir", default=None)
    args = parser.parse_args()
    metrics = train_and_save(args.out_dir)
    print(json.dumps(metrics, ensure_ascii=False))


if __name__ == "__main__":
    main()
