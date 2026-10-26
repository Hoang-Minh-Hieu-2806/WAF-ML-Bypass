"""Compute ML threshold trade-offs from one run_experiment results.json.

The script deduplicates repeated PL rows by case_id because the ML score is
independent from CRS paranoia level. It never rewrites experiment evidence.
"""
import argparse
import json
from pathlib import Path


def metrics(rows, threshold):
    malicious = [row for row in rows if row["label"] == "malicious"]
    benign = [row for row in rows if row["label"] == "benign"]
    tp = sum(float(row["ml"]["score"]) >= threshold for row in malicious)
    fn = len(malicious) - tp
    fp = sum(float(row["ml"]["score"]) >= threshold for row in benign)
    tn = len(benign) - fp
    ratio = lambda a, b: round(100 * a / b, 2) if b else None
    precision = ratio(tp, tp + fp)
    recall = ratio(tp, tp + fn)
    f1 = ratio(2 * tp, 2 * tp + fp + fn) or 0.0
    return {"threshold": threshold, "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision_pct": precision, "recall_pct": recall, "f1_pct": f1,
            "fpr_pct": ratio(fp, fp + tn)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("results", type=Path)
    parser.add_argument("--thresholds", nargs="+", type=float,
                        default=[0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9])
    args = parser.parse_args()
    raw = json.loads(args.results.read_text(encoding="utf-8"))
    by_case = {}
    for row in raw:
        if (row.get("ml") or {}).get("score") is not None:
            previous = by_case.setdefault(row["case_id"], row)
            if previous is not row:
                previous_signature = (previous["label"], previous["ml"]["score"],
                                      previous["ml"].get("model_version"))
                current_signature = (row["label"], row["ml"]["score"],
                                     row["ml"].get("model_version"))
                if current_signature != previous_signature:
                    raise SystemExit(f"Inconsistent repeated ML result: {row['case_id']}")
    if not by_case:
        raise SystemExit("No ML scores found in results")
    print("| Threshold | TP | FP | FN | TN | Precision | Recall | F1 | FPR |")
    print("|---:|---:|---:|---:|---:|---:|---:|---:|---:|")
    for value in args.thresholds:
        if not 0 <= value <= 1:
            raise SystemExit(f"Invalid threshold: {value}")
        row = metrics(list(by_case.values()), value)
        print("| {threshold:.2f} | {tp} | {fp} | {fn} | {tn} | "
              "{precision_pct}% | {recall_pct}% | {f1_pct}% | {fpr_pct}% |".format(**row))


if __name__ == "__main__":
    main()
