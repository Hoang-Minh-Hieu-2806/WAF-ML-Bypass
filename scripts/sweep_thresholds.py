"""Compute ML threshold trade-offs from one run_experiment results.json.

The script deduplicates repeated PL rows by case_id because the ML score is
independent from CRS paranoia level. It never rewrites experiment evidence.

Threshold sweep uses the P1 attack-sum policy (design §10): a case is blocked
when its attack score, p_sqli + p_xss for three-class models, exceeds the
threshold; legacy single-class runs fall back to ml.score. The P2 max-class
policy (blocked when the argmax class is an attack class) is threshold
independent and reported side by side for comparison.
"""
import argparse
import json
from pathlib import Path


EVIDENCE_SOURCES = ("ml", "ml_enforcement", "hybrid_ml_evidence")


def evidence(row):
    """First available ML record with a usable score, per RUN-A/RUN-B layout."""
    for source in EVIDENCE_SOURCES:
        record = row.get(source) or {}
        if record.get("attack_score") is not None or record.get("score") is not None:
            return record
    return {}


def attack_score(row):
    """P1 attack score: attack-class sum for v1.1, legacy ml.score for v1.0."""
    record = evidence(row)
    score = record.get("attack_score")
    if score is None:
        score = record.get("score")
    return None if score is None else float(score)


def max_class_policy(row):
    """P2: blocked when the argmax class is an attack class; None if unavailable."""
    scores = evidence(row).get("scores")
    if not isinstance(scores, dict) or not scores:
        return None
    return max(scores.items(), key=lambda item: item[1])[0] != "benign"


def _split(rows):
    malicious = [row for row in rows if row["label"] == "malicious"]
    benign = [row for row in rows if row["label"] == "benign"]
    return malicious, benign


def metrics(rows, threshold):
    """P1 confusion-matrix trade-off at one attack-sum threshold."""
    malicious, benign = _split(rows)
    mal_scores = [attack_score(row) for row in malicious]
    ben_scores = [attack_score(row) for row in benign]
    if any(score is None for score in mal_scores + ben_scores):
        raise SystemExit("Threshold sweep found a row without ML evidence")
    tp = sum(score >= threshold for score in mal_scores)
    fn = len(mal_scores) - tp
    fp = sum(score >= threshold for score in ben_scores)
    tn = len(ben_scores) - fp
    return {**_rates(tp, fp, fn, tn), "threshold": threshold}


def p2_metrics(rows):
    """P2 max-class policy trade-off (threshold independent); None if unavailable."""
    malicious, benign = _split(rows)
    mal_decisions = [max_class_policy(row) for row in malicious]
    ben_decisions = [max_class_policy(row) for row in benign]
    if any(decision is None for decision in mal_decisions + ben_decisions):
        return None
    tp = sum(mal_decisions)
    fn = len(mal_decisions) - tp
    fp = sum(ben_decisions)
    tn = len(ben_decisions) - fp
    return _rates(tp, fp, fn, tn)


def _rates(tp, fp, fn, tn):
    ratio = lambda a, b: round(100 * a / b, 2) if b else None
    precision = ratio(tp, tp + fp)
    recall = ratio(tp, tp + fn)
    f1 = ratio(2 * tp, 2 * tp + fp + fn) or 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
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
        record = evidence(row)
        if record.get("attack_score") is not None or record.get("score") is not None:
            previous = by_case.setdefault(row["case_id"], row)
            if previous is not row:
                def signature(candidate):
                    candidate_record = evidence(candidate)
                    return (candidate["label"], candidate_record.get("attack_score"),
                            candidate_record.get("score"),
                            candidate_record.get("model_version"))
                if signature(row) != signature(previous):
                    raise SystemExit(f"Inconsistent repeated ML result: {row['case_id']}")
    if not by_case:
        raise SystemExit("No ML scores found in results")
    rows = list(by_case.values())
    p2 = p2_metrics(rows)
    print("| Threshold | P1 TP | P1 FP | P1 FN | P1 TN | P1 Precision | P1 Recall | "
          "P1 F1 | P1 FPR | P2 TP | P2 FP | P2 FN | P2 TN | P2 Precision | P2 Recall | "
          "P2 F1 | P2 FPR |")
    print("|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|")
    for value in args.thresholds:
        if not 0 <= value <= 1:
            raise SystemExit(f"Invalid threshold: {value}")
        p1 = metrics(rows, value)
        p2_cells = ("n/a",) * 8 if p2 is None else tuple(
            p2[key] for key in ("tp", "fp", "fn", "tn", "precision_pct",
                                "recall_pct", "f1_pct", "fpr_pct"))
        print(("| {threshold:.2f} | {tp} | {fp} | {fn} | {tn} | "
               "{precision_pct}% | {recall_pct}% | {f1_pct}% | {fpr_pct}% | "
              ).format(**p1) + " | ".join(str(cell) for cell in p2_cells) + " |")
    if p2 is None:
        print("P2 max-class policy unavailable (no per-class scores in evidence; "
              "legacy v1.0 runs only).")


if __name__ == "__main__":
    main()
