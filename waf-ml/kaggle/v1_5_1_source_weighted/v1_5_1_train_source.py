# %% [markdown]
# # T03 — v1.5.1 candidate: source-weighted full Mendeley XSS training
#
# Protocol (locked 2026-11-14, from `report/execution-plan-v3.1-2-tuan.md` and the
# v1.4 pipeline `waf-ml/train_xss_augmented.py`):
#
# 1. Inputs are verified by SHA-256 before anything runs. Abort on mismatch.
# 2. Full Mendeley file (`xss_dataset.csv`) is the source; ~20% held out by the
#    same deterministic method as v1.4 (SHA-256 first-byte buckets < 51/256).
#    No reservoir quotas — the whole file is split between train and holdout.
# 3. Dedup normalization is `strip + lowercase`, identical to v1.3/v1.4.
# 4. Payloads present in HttpParams train/test or the lab corpus are excluded
#    from BOTH Mendeley splits (leakage control).
# 5. Same locked pipeline: TfidfVectorizer(char_wb, ngram (1,2), sublinear_tf,
#    min_df=1) + LogisticRegression(C=2.0, max_iter=2000). Threshold 0.5.
# 6. Pilot mode: `PILOT_TRAIN_ROWS` (e.g. 100000) subsamples ONLY the Mendeley
#    train portion to measure time/RAM; holdout evaluation is always on the
#    full holdout.
# 7. Mendeley rows all remain in fit; sample weights cap their total classifier
#    influence to the v1.4 contribution (12,288 effective rows). HttpParams/lab
#    rows retain weight 1. Pilot subsamples Mendeley only.
# 8. Limitations unchanged: source payloads are safety-neutralized, holdout is
#    payload-level (not family-disjoint), and no family/source metadata exists.
#    Results are text-classification evidence, not executable-XSS proof.
#
# Promotion rule (pre-committed): v1.5 becomes the served model only if the
# 37-case lab RUN-A/RUN-B show no new miss or false positive vs v1.1/v1.3/v1.4
# and per-class metrics meet A1–A7. A larger dataset is not a promotion reason
# by itself.

# %%
import hashlib
import importlib.metadata
import os
import platform
import subprocess
import sys
from pathlib import Path
from packaging.tags import sys_tags
from packaging.utils import parse_wheel_filename
from packaging.version import Version

TRAINING_MODE = os.getenv("TRAINING_MODE", "candidate").strip().lower()
if TRAINING_MODE == "baseline":
    # Reproduce baseline v1.5 in the preserved `minhiuwu/v15-train` notebook.
    raise RuntimeError("Baseline mode is the preserved v15-train kernel; do not run candidate code as baseline.")
if TRAINING_MODE != "candidate":
    raise RuntimeError(f"Unknown TRAINING_MODE={TRAINING_MODE!r}; use candidate or the preserved baseline kernel.")

EXPECTED_SKLEARN = Version("1.7.1")
SKLEARN_WHEEL_SHA256 = "13679981fdaebc10cc4c13c43344416a86fcbc61449cb3e6517e1df9d12c8309"
wheel_hint = os.getenv("SKLEARN_WHEEL_PATH")
search_roots = [Path(wheel_hint)] if wheel_hint else [Path("/kaggle/input")]
wheel_candidates = []
for root in search_roots:
    if root.is_file():
        wheel_candidates.extend(sorted(root.parent.rglob("*.whl")))
    elif root.is_dir():
        wheel_candidates.extend(sorted(root.rglob("*.whl")))
wheel_path = next((p for p in wheel_candidates
                   if hashlib.sha256(p.read_bytes()).hexdigest() == SKLEARN_WHEEL_SHA256), None)
if wheel_path is None:
    raise FileNotFoundError(
        "Candidate requires the checksum-matching scikit-learn 1.7.1 wheel. "
        "Attach its private Kaggle dataset or set SKLEARN_WHEEL_PATH to the wheel/file directory."
    )
wheel_name, wheel_version, _, wheel_tags = parse_wheel_filename(wheel_path.name)
runtime_tags = set(sys_tags())
print("Python:", platform.python_version(), "OS:", platform.system(),
      "architecture:", platform.machine(), "wheel tags:", sorted(map(str, wheel_tags)))
if wheel_name != "scikit-learn" or wheel_version != EXPECTED_SKLEARN:
    raise RuntimeError(f"Wrong wheel: {wheel_path.name}; need scikit-learn==1.7.1")
if not runtime_tags.intersection(wheel_tags):
    raise RuntimeError(
        f"Wheel is incompatible: Python {platform.python_version()}, "
        f"{platform.system()} {platform.machine()}, tags={sorted(map(str, wheel_tags))}"
    )

# These are the runtime requirements declared by scikit-learn 1.7.1.
required_dependencies = {"numpy": Version("1.22.0"), "scipy": Version("1.8.0"),
                         "joblib": Version("1.2.0"), "threadpoolctl": Version("3.1.0")}
missing_dependencies = []
for package, minimum in required_dependencies.items():
    try:
        installed = Version(importlib.metadata.version(package))
    except importlib.metadata.PackageNotFoundError:
        installed = None
    if installed is None or installed < minimum:
        wheel_ok = False
        for candidate in wheel_candidates:
            try:
                name, version, _, tags = parse_wheel_filename(candidate.name)
            except Exception:
                continue
            if name == package and version >= minimum and runtime_tags.intersection(tags):
                wheel_ok = True
                break
        if not wheel_ok:
            missing_dependencies.append(f"{package}>={minimum} (installed={installed or 'missing'}, compatible offline wheel={'missing'})")
if missing_dependencies:
    raise RuntimeError("Offline dependency check failed: " + "; ".join(missing_dependencies))

try:
    current_sklearn = Version(importlib.metadata.version("scikit-learn"))
except importlib.metadata.PackageNotFoundError:
    current_sklearn = None
if current_sklearn != EXPECTED_SKLEARN:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "--quiet", "--no-index",
                           "--find-links", str(wheel_path.parent), "scikit-learn==1.7.1"])

import csv
import io
import json
import random
import time
from collections import Counter

import numpy as np
import sklearn
import scipy
assert sklearn.__version__ == "1.7.1", ("Candidate requires scikit-learn 1.7.1", sklearn.__version__)
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, average_precision_score, confusion_matrix, f1_score,
                             precision_recall_fscore_support, roc_auc_score)
from sklearn.pipeline import Pipeline

MODEL_VERSION = "lr-tfidf-3cls-1.5.1"
THRESHOLD = 0.5
CLASS_ORDER = ["benign", "sqli", "xss"]
HOLDOUT_BUCKET_CUTOFF = 51  # first-byte buckets < 51/256 ~= 20% holdout (same as v1.4)
SEED = 20261115
MENDELEY_EFFECTIVE_WEIGHT = 12_288  # Match v1.4: 8,192 XSS + 4,096 benign rows
PILOT_TRAIN_ROWS = int(os.getenv("PILOT_TRAIN_ROWS", "0"))  # 0 = full; pilot was validated in kernel version 4

# Expected input hashes (locked from v1.3/v1.4 metrics.json)
EXPECTED_SHA256 = {
    "xss_dataset.csv": "81648bab21a3f2859d50fa679fa2b34f54486b920c183460a3efcbbbcc43af4c",
    "payload_train.csv": "dfa6e59c87b2bafc485c9cb14d37e3f86607d180e5a22e7c46dae6d3d1dd6a16",
    "payload_test.csv": "d8015e256ce4499c8ac7a8be8dd25de6487cf018601edf1a03a408a2c8f0e39d",
    "lab_corpus_rows.csv": "02ab25f40f42eec43ffd392566e0eacd3da77c9366ba08b9e1b2c4c887c8281a",
}

# Locate inputs BY HASH (name-independent): scan every CSV under /kaggle/input.
def _sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


hash_to_name = {digest: name for name, digest in EXPECTED_SHA256.items()}
INPUT_FILES = {}
seen_csvs = []
for base in [Path("/kaggle/input"), Path(".")]:
    if not base.exists():
        continue
    for path in sorted(base.rglob("*.csv")):
        key = str(path)
        if key in seen_csvs:
            continue
        seen_csvs.append(key)
        digest = _sha256_file(path)
        if digest in hash_to_name:
            INPUT_FILES[hash_to_name[digest]] = path

missing = [name for name in EXPECTED_SHA256 if name not in INPUT_FILES]
print(f"CSV files seen under input: {len(seen_csvs)}")
for path in seen_csvs:
    print(f"  {path}")
if missing:
    raise AssertionError(
        f"Inputs missing (matched by SHA-256): {missing}. "
        "Check that the Kaggle dataset is attached to this notebook (Add Input) "
        "and contains the 4 required files.")
for name, path in INPUT_FILES.items():
    print(f"OK  {name}  ->  {path}")
print("sklearn:", sklearn.__version__)


# %%
def normalize(text):
    return text.strip().lower()


def dedupe(rows):
    out, seen = [], set()
    for text, label in rows:
        key = normalize(text)
        if key and key not in seen:
            seen.add(key)
            out.append((text, label))
    return out, seen, len(rows) - len(out)


def load_http_rows(path):
    label_map = {"norm": "benign", "sqli": "sqli", "xss": "xss"}
    rows = []
    with open(path, newline="", encoding="utf-8-sig") as stream:
        reader = csv.DictReader(stream)
        assert {"payload", "attack_type"}.issubset(reader.fieldnames or [])
        for row in reader:
            label = label_map.get((row.get("attack_type") or "").strip().lower())
            text = (row.get("payload") or "").strip()
            if label and text:
                rows.append((text, label))
    assert {label for _, label in rows} == set(CLASS_ORDER)
    return rows


t0 = time.time()
http_train_rows, http_train_keys, http_train_dups = dedupe(load_http_rows(INPUT_FILES["payload_train.csv"]))
http_test_rows, http_test_keys, http_test_dups = dedupe(load_http_rows(INPUT_FILES["payload_test.csv"]))
lab_rows, lab_keys, lab_dups = dedupe([
    (row["text"], row["label"])
    for row in csv.DictReader(open(INPUT_FILES["lab_corpus_rows.csv"], encoding="utf-8"))
])
external_keys = set(http_train_keys) | set(http_test_keys) | set(lab_keys)
print(f"http train {len(http_train_rows)} (dups {http_train_dups})  "
      f"http test {len(http_test_rows)} (dups {http_test_dups})  "
      f"lab {len(lab_rows)} (dups {lab_dups})  [{time.time()-t0:.1f}s]")


# %%
# Stream the full Mendeley file: dedup, conflict check, exclusion, SHA-256 split.
t0 = time.time()
split_train, split_holdout = [], []
seen_mendeley = {}
stats = Counter()
label_counts = Counter()
source_hash = hashlib.sha256()
with open(INPUT_FILES["xss_dataset.csv"], "rb") as raw:
    for block in iter(lambda: raw.read(1024 * 1024), b""):
        source_hash.update(block)
assert source_hash.hexdigest() == EXPECTED_SHA256["xss_dataset.csv"]

with open(INPUT_FILES["xss_dataset.csv"], newline="", encoding="utf-8-sig") as stream:
    reader = csv.DictReader(stream)
    assert {"Query", "Label"}.issubset(reader.fieldnames or [])
    for row in reader:
        stats["rows_seen"] += 1
        label = (row.get("Label") or "").strip()
        text = (row.get("Query") or "").strip()
        if label not in ("0", "1"):
            stats["bad_label"] += 1
            continue
        stats["label_counts_seen"] += 1
        label_counts[label] += 1
        if not text:
            stats["empty"] += 1
            continue
        key = text.lower()  # Mendeley internal dedup: lowercase (as v1.4)
        if key in seen_mendeley:
            stats["duplicates"] += 1
            stats["conflicting"] += seen_mendeley[key] != label
            continue
        seen_mendeley[key] = label
        if normalize(text) in external_keys:
            stats["overlap_excluded"] += 1
            continue
        bucket = hashlib.sha256(key.encode("utf-8")).digest()[0]
        target = split_holdout if bucket < HOLDOUT_BUCKET_CUTOFF else split_train
        target.append((text, "xss" if label == "1" else "benign"))

assert stats["conflicting"] == 0, f"conflicting duplicate labels: {stats['conflicting']}"
holdout = split_holdout
mendeley_train = split_train
print(f"Mendeley: {stats['rows_seen']} rows seen, unique non-empty {len(seen_mendeley)}")
print(f"  duplicates {stats['duplicates']} (conflicting {stats['conflicting']}), empty {stats['empty']}, overlap excluded {stats['overlap_excluded']}")
print(f"  train {len(mendeley_train)} {Counter(y for _, y in mendeley_train)}")
print(f"  holdout {len(holdout)} {Counter(y for _, y in holdout)}  [{time.time()-t0:.1f}s]")


# %%
# Keep every HttpParams/lab row at weight 1; cap Mendeley influence to v1.4's effective 12,288 rows.
t0 = time.time()
base_rows = http_train_rows + [
    row for row in lab_rows if normalize(row[0]) not in http_train_keys
]
mendeley_fit_rows = mendeley_train
pilot_excluded = 0
if PILOT_TRAIN_ROWS and PILOT_TRAIN_ROWS < len(mendeley_fit_rows):
    rng = random.Random(SEED)
    keep = sorted(rng.sample(range(len(mendeley_fit_rows)), PILOT_TRAIN_ROWS))
    pilot_before = len(mendeley_fit_rows)
    mendeley_fit_rows = [mendeley_fit_rows[i] for i in keep]
    pilot_excluded = pilot_before - len(mendeley_fit_rows)
    print(f"PILOT: Mendeley train reduced to {len(mendeley_fit_rows)} rows; "
          f"HttpParams/lab kept at {len(base_rows)} rows")
fit_rows = base_rows + mendeley_fit_rows
fit_keys = [normalize(text) for text, _ in fit_rows]
fit_dups = len(fit_keys) - len(set(fit_keys))
assert fit_dups == 0, f"combined fit duplicates: {fit_dups}"
fit_sample_weight = ([1.0] * len(base_rows) +
                     [MENDELEY_EFFECTIVE_WEIGHT / len(mendeley_fit_rows)] * len(mendeley_fit_rows))
assert len(fit_sample_weight) == len(fit_rows)
assert abs(sum(fit_sample_weight[len(base_rows):]) - MENDELEY_EFFECTIVE_WEIGHT) < 1e-6
print(f"fit rows {len(fit_rows)} {Counter(y for _, y in fit_rows)} "
      f"(combined dups removed {fit_dups}); source weight sums: "
      f"base={sum(fit_sample_weight[:len(base_rows)]):.1f}, "
      f"Mendeley={sum(fit_sample_weight[len(base_rows):]):.1f} "
      f"[{time.time()-t0:.1f}s]")

# HttpParams test stays clean of lab overlap (same rule as v1.3/v1.4)
test_excluded = sum(normalize(text) in lab_keys for text, _ in http_test_rows)
http_test_clean = [row for row in http_test_rows
                   if normalize(row[0]) not in lab_keys]
print(f"http test clean {len(http_test_clean)} ({test_excluded} excluded for lab overlap)")


# %%
# Locked pipeline (identical hyperparameters to v1.1–v1.4)
def build_pipeline():
    return Pipeline([
        ("tfidf", TfidfVectorizer(analyzer="char_wb", ngram_range=(1, 2),
                                  sublinear_tf=True, min_df=1)),
        ("clf", LogisticRegression(max_iter=2000, C=2.0)),
    ])


def peak_mb():
    try:
        import resource
        return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024
    except Exception:
        return float("nan")


t0 = time.time()
model = build_pipeline().fit(
    [text for text, _ in fit_rows], [label for _, label in fit_rows],
    clf__sample_weight=np.asarray(fit_sample_weight, dtype=np.float64))
fit_seconds = time.time() - t0
print(f"fit {fit_seconds:.1f}s  peak RSS ~{peak_mb():.0f} MB")


# %%
def metric_block(model, rows):
    texts, labels = zip(*rows)
    y_true = np.asarray(labels)
    y_pred = model.predict(texts)
    probabilities = model.predict_proba(texts)
    benign = y_true == "benign"
    attack_prob = (probabilities[:, list(model.classes_).index("sqli")] +
                   probabilities[:, list(model.classes_).index("xss")])
    present = [label for label in CLASS_ORDER if np.any(y_true == label)]
    precision, recall, f1, support = precision_recall_fscore_support(
        y_true, y_pred, labels=CLASS_ORDER, zero_division=0)
    return {
        "rows": len(rows),
        "class_counts": dict(Counter(labels)),
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "macro_f1": float(f1_score(y_true, y_pred, labels=present,
                                   average="macro", zero_division=0)),
        "weighted_f1": float(f1_score(y_true, y_pred, labels=present,
                                      average="weighted", zero_division=0)),
        "macro_f1_labels": present,
        "per_class": {label: {"precision": float(precision[i]),
                              "recall": float(recall[i]),
                              "f1": float(f1[i]),
                              "support": int(support[i])}
                      for i, label in enumerate(CLASS_ORDER)},
        "confusion_labels": CLASS_ORDER,
        "confusion_matrix": confusion_matrix(y_true, y_pred, labels=CLASS_ORDER).tolist(),
        "benign_to_sqli_fpr": float(np.mean(y_pred[benign] == "sqli")),
        "benign_to_xss_fpr": float(np.mean(y_pred[benign] == "xss")),
        "binary_attack_policy": {
            "policy": "P(sqli) + P(xss) >= threshold",
            "threshold": THRESHOLD,
            "confusion_labels": ["benign", "malicious"],
            "confusion_matrix": confusion_matrix(y_true != "benign", attack_prob >= THRESHOLD,
                                                 labels=[False, True]).tolist(),
            "precision": float(precision_recall_fscore_support(
                y_true != "benign", attack_prob >= THRESHOLD, labels=[True],
                zero_division=0)[0][0]),
            "recall": float(precision_recall_fscore_support(
                y_true != "benign", attack_prob >= THRESHOLD, labels=[True],
                zero_division=0)[1][0]),
            "f1": float(f1_score(y_true != "benign", attack_prob >= THRESHOLD,
                                 zero_division=0)),
            "roc_auc": float(roc_auc_score(y_true != "benign", attack_prob))
                       if len(np.unique(y_true != "benign")) == 2 else None,
            "pr_auc_average_precision": float(average_precision_score(
                y_true != "benign", attack_prob))
                if len(np.unique(y_true != "benign")) == 2 else None,
        },
    }


t0 = time.time()
evaluation = {
    "mendeley_payload_holdout": metric_block(model, holdout),
    "httpparams_external_test": metric_block(model, http_test_clean),
}
for name, block in evaluation.items():
    print(f"\n{name}: rows={block['rows']} acc={block['accuracy']:.6f} "
          f"macro_f1={block['macro_f1']:.6f} P1_F1={block['binary_attack_policy']['f1']:.6f}")
    for label in block["macro_f1_labels"]:
        pc = block["per_class"][label]
        print(f"  {label}: P={pc['precision']:.4f} R={pc['recall']:.4f} F1={pc['f1']:.4f} n={pc['support']}")
print(f"[{time.time()-t0:.1f}s]")


# %%
metrics = {
    "model_version": MODEL_VERSION,
    "sklearn_version": sklearn.__version__,
    "training_mode": TRAINING_MODE,
    "python_version": platform.python_version(),
    "operating_system": platform.platform(),
    "architecture": platform.machine(),
    "numpy_version": np.__version__,
    "scipy_version": scipy.__version__,
    "joblib_version": importlib.metadata.version("joblib"),
    "threadpoolctl_version": importlib.metadata.version("threadpoolctl"),
    "sklearn_wheel_sha256": SKLEARN_WHEEL_SHA256,
    "sklearn_wheel_tags": sorted(map(str, wheel_tags)),
    "pilot": {"enabled": bool(PILOT_TRAIN_ROWS), "fit_rows_target": PILOT_TRAIN_ROWS,
              "rows_excluded": pilot_excluded},
    "dataset": {
        "sources": ["Morzeux/HttpParamsDataset", "dataset/bypass (lab_corpus_rows.csv)",
                    "Mendeley XSS dataset DOI 10.17632/py6cnbgdh2.2 (full file)"],
        "http_train_class_counts": dict(Counter(y for _, y in http_train_rows)),
        "lab_class_counts": dict(Counter(y for _, y in lab_rows)),
        "mendeley_rows_seen": stats["rows_seen"],
        "mendeley_label_counts": dict(label_counts),
        "mendeley_unique_nonempty_rows": len(seen_mendeley),
        "mendeley_train_rows": len(mendeley_train),
        "mendeley_holdout_rows": len(holdout),
        "mendeley_holdout_class_counts": dict(Counter(y for _, y in holdout)),
        "fit_class_counts": dict(Counter(y for _, y in fit_rows)),
        "fit_rows": len(fit_rows),
        "fit_rows_by_source": {"httpparams_and_lab": len(base_rows),
                                "mendeley_xss": len(mendeley_fit_rows)},
        "sample_weight_sums": {"httpparams_and_lab": float(sum(fit_sample_weight[:len(base_rows)])),
                                "mendeley_xss": float(sum(fit_sample_weight[len(base_rows):]))},
        "mendeley_effective_weight_target": MENDELEY_EFFECTIVE_WEIGHT,
        "scikit_learn_wheel_sha256": SKLEARN_WHEEL_SHA256,
        "http_test_rows_clean": len(http_test_clean),
        "dedup": {
            "normalization": "strip + lowercase",
            "http_train_internal": http_train_dups,
            "http_test_internal": http_test_dups,
            "lab_internal": lab_dups,
            "mendeley_duplicates": stats["duplicates"],
            "mendeley_conflicting_duplicate_labels": stats["conflicting"],
            "mendeley_empty_payload_rows": stats["empty"],
            "mendeley_bad_label_rows": stats["bad_label"],
            "mendeley_overlap_excluded_both_splits": stats["overlap_excluded"],
            "combined_fit_duplicates_removed": fit_dups,
            "http_test_excluded_for_lab_overlap": test_excluded,
        },
        "split": {
            "method": "deterministic SHA-256 payload hash; first-byte buckets < "
                      f"{HOLDOUT_BUCKET_CUTOFF}/256 (~{HOLDOUT_BUCKET_CUTOFF/256:.1%}) held out; "
                      "no reservoir quotas (full file)",
            "holdout_bucket_cutoff": HOLDOUT_BUCKET_CUTOFF,
            "pilot_seed": SEED,
        },
        "sha256": EXPECTED_SHA256,
    },
    "features": "TfidfVectorizer char_wb ngram_range=(1,2), sublinear_tf=True, min_df=1",
    "model": "LogisticRegression C=2.0, max_iter=2000, class_weight=None; one source sample_weight vector passed once",
    "threshold": THRESHOLD,
    "fit_seconds": fit_seconds,
    "peak_rss_mb_after_fit": peak_mb(),
    "peak_rss_mb": peak_mb(),
    "evaluation": evaluation,
    "evaluation_note": (
        "v1.5.1 uses the FULL Mendeley XSS source with sample weights capped to the v1.4 "
        "effective contribution (12,288 Mendeley rows); HttpParams/lab rows retain weight 1. "
        "The split is ~20% payload-level with SHA-256 buckets < 51/256 and no quotas. "
        "Source payloads are "
        "safety-neutralized and lack family/source metadata; the holdout is payload-level, "
        "not family-disjoint. Results measure text classification, not executable XSS. "
        "Candidate only: compare with v1.4/v1.3/v1.1 and re-run the 37-case lab (RUN-A, "
        "RUN-B, PL1-3) before any promotion. Promotion requires no new lab miss or false "
        "positive and A1-A7 per-class thresholds."
    ),
}
out = Path("/kaggle/working") if Path("/kaggle/working").exists() else Path("artifacts_v1_5_local")
out.mkdir(parents=True, exist_ok=True)
import joblib
joblib.dump(model, out / "model.joblib", compress=3)
(out / "metrics.json").write_text(json.dumps(metrics, indent=2, ensure_ascii=False), encoding="utf-8")
(out / "model.joblib.sha256").write_text(
    hashlib.sha256((out / "model.joblib").read_bytes()).hexdigest() + "\n", encoding="ascii")
(out / "metrics.json.sha256").write_text(
    hashlib.sha256((out / "metrics.json").read_bytes()).hexdigest() + "\n", encoding="ascii")
reloaded_model = joblib.load(out / "model.joblib")
probe_texts = [text for text, _ in fit_rows[:min(8, len(fit_rows))]]
assert list(reloaded_model.classes_) == CLASS_ORDER
assert np.array_equal(reloaded_model.predict(probe_texts), model.predict(probe_texts))
metrics["artifact_reload_selfcheck"] = True
metrics["model_classes"] = list(reloaded_model.classes_)
(out / "metrics.json").write_text(json.dumps(metrics, indent=2, ensure_ascii=False), encoding="utf-8")
(out / "metrics.json.sha256").write_text(
    hashlib.sha256((out / "metrics.json").read_bytes()).hexdigest() + "\n", encoding="ascii")
print("saved:", [p.name for p in out.iterdir() if p.is_file()])
print("model sha256:", (out / "model.joblib.sha256").read_text().strip()[:16], "…")
print("metrics sha256:", (out / "metrics.json.sha256").read_text().strip()[:16], "…")
