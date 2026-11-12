"""A6: compare SQLi case outcomes of a v1.1 run against the v1.0 baseline.

Design §9.5: every SQLi case must produce the same outcome per (config, PL);
flips are allowed only when the ML threshold policy changed polarity
(v1.0 ml.score >= 0.5 vs v1.1 attack_score >= 0.5) and the new blocking layer
is consistent with it. Any other flip is unexplained and fails A6.

Usage:
  python scripts/compare_a6_baseline.py \
      --baseline results/raw/experiments/<v1.0-run> \
      --candidate results/raw/experiments/<v1.1-run>
"""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_SOURCES = ("ml_enforcement", "hybrid_ml_evidence", "ml")
THRESHOLD = 0.5


def load_rows(directory):
    path = Path(directory)
    results = path / "results.json" if not path.name.endswith(".json") else path
    if not results.is_file():
        raise SystemExit(f"results.json not found under {directory}")
    rows = json.loads(results.read_text(encoding="utf-8"))
    metadata = {}
    meta_path = results.parent / "metadata.json"
    if meta_path.is_file():
        metadata = json.loads(meta_path.read_text(encoding="utf-8"))
    return rows, metadata


def is_sqli_malicious(row):
    if row.get("label") != "malicious":
        return False
    return row.get("vuln", "sqli") == "sqli"


def evidence(row):
    for source in EVIDENCE_SOURCES:
        record = row.get(source) or {}
        scores = record.get("scores")
        if (record.get("attack_score") is not None or record.get("score") is not None
                or (isinstance(scores, dict) and {"sqli", "xss"} <= set(scores))):
            return record
    return {}


def ml_attack_score(row):
    record = evidence(row)
    attack_score = record.get("attack_score")
    if attack_score is None:
        scores = record.get("scores")
        if isinstance(scores, dict) and {"sqli", "xss"} <= set(scores):
            attack_score = scores["sqli"] + scores["xss"]
    if attack_score is None:
        attack_score = record.get("score")
    return None if attack_score is None else float(attack_score)


def polarity(row):
    score = ml_attack_score(row)
    return None if score is None else score >= THRESHOLD


def outcome_key(row):
    return (row["case_id"], row["paranoia_level"])


def collect_sqli_map(rows):
    return {outcome_key(row): row for row in rows if is_sqli_malicious(row)}


def compare(baseline_rows, candidate_rows):
    base_map = collect_sqli_map(baseline_rows)
    cand_map = collect_sqli_map(candidate_rows)
    shared = sorted(set(base_map) & set(cand_map),
                    key=lambda key: (key[0], key[1]))
    only_baseline = sorted(set(base_map) - set(cand_map))
    only_candidate = sorted(set(cand_map) - set(base_map))
    same, flips = 0, []
    for key in shared:
        base, cand = base_map[key], cand_map[key]
        if base["outcome"] == cand["outcome"]:
            same += 1
            continue
        base_polarity, cand_polarity = polarity(base), polarity(cand)
        explained = (base_polarity is not None and cand_polarity is not None
                     and base_polarity != cand_polarity
                     and flip_consistent_with_layer(base, cand))
        flips.append({"case_id": key[0], "paranoia_level": key[1],
                      "baseline_outcome": base["outcome"],
                      "candidate_outcome": cand["outcome"],
                      "baseline_ml_score": ml_attack_score(base),
                      "candidate_attack_score": ml_attack_score(cand),
                      "baseline_polarity": base_polarity,
                      "candidate_polarity": cand_polarity,
                      "candidate_blocking_layer": cand.get("blocking_layer"),
                      "threshold_policy_explains_flip": explained})
    return {"shared": len(shared), "same_outcome": same, "flips": flips,
            "only_in_baseline": only_baseline, "only_in_candidate": only_candidate}


def flip_consistent_with_layer(base, cand):
    """In hybrid runs an ML-driven flip must match the recorded blocking layer."""
    base_polarity, cand_polarity = polarity(base), polarity(cand)
    layer = cand.get("blocking_layer")
    became_blocked = base["outcome"] != "blocked" and cand["outcome"] == "blocked"
    became_allowed = base["outcome"] == "blocked" and cand["outcome"] != "blocked"
    if became_blocked:
        return layer == "ml" and cand_polarity is True and base_polarity is False
    if became_allowed:
        return cand_polarity is False and base_polarity is True
    return base_polarity is not None and cand_polarity is not None \
        and base_polarity != cand_polarity


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", required=True,
                        help="v1.0 run directory (or results.json)")
    parser.add_argument("--candidate", required=True,
                        help="v1.1 run directory (or results.json)")
    args = parser.parse_args()
    baseline_rows, baseline_meta = load_rows(args.baseline)
    candidate_rows, candidate_meta = load_rows(args.candidate)
    result = compare(baseline_rows, candidate_rows)
    print(f"A6 SQLi regression: baseline={Path(args.baseline).name} "
          f"candidate={Path(args.candidate).name}")
    print(f"shared case-rounds: {result['shared']} | same outcome: "
          f"{result['same_outcome']} | flips: {len(result['flips'])}")
    if result["only_in_baseline"] or result["only_in_candidate"]:
        print("WARNING unmatched keys — baseline/candidate cover different case sets")
    for flip in result["flips"]:
        state = "EXPLAINED" if flip["threshold_policy_explains_flip"] else "UNEXPLAINED"
        print(f"  {flip['case_id']} PL{flip['paranoia_level']}: "
              f"{flip['baseline_outcome']} -> {flip['candidate_outcome']} [{state}] "
              f"(ml {flip['baseline_ml_score']} -> {flip['candidate_attack_score']}, "
              f"layer={flip['candidate_blocking_layer']})")
    unexplained = [flip for flip in result["flips"]
                   if not flip["threshold_policy_explains_flip"]]
    if unexplained:
        print(f"A6 FAIL: {len(unexplained)} unexplained flip(s)")
        return 1
    print("A6 PASS: all outcome flips explained by threshold policy" if result["flips"]
          else "A6 PASS: no outcome flips")
    return 0


if __name__ == "__main__":
    sys.exit(main())
