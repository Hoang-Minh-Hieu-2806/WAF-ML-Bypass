# R11 — Threshold sweep v1.1 (2026-11-12)

## Scope and source

- Source run: RUN-A `20261112T151032Z-6eea4579` (`crs_backend=direct`); the sweep reads the standalone ML evidence recorded in the run.
- Corpus: 36 unique cases, deduplicated by `case_id`: 21 malicious (15 SQLi + 6 XSS) and 15 benign (11 SQLi + 4 XSS).
- Model: `lr-tfidf-3cls-1.1`, as recorded in the run metadata and per-row ML evidence.
- Command used:

  ```powershell
  python scripts/sweep_thresholds.py results/raw/experiments/20261112T151032Z-6eea4579/results.json --thresholds 0.4 0.5 0.6 0.7
  ```

P1 uses the three-class attack sum `P(sqli) + P(xss)` and compares it with the listed threshold. P2 blocks when the maximum-probability class is an attack class; its result does not depend on the threshold. Each row below reports TP, FP, FN, TN, F1, and benign FPR.

## Results

| Threshold | P1 TP/FP/FN/TN | P1 F1 | P1 FPR | P2 TP/FP/FN/TN | P2 F1 | P2 FPR |
|---:|---:|---:|---:|---:|---:|---:|
| 0.40 | 21 / 0 / 0 / 15 | 100% | 0% | 21 / 0 / 0 / 15 | 100% | 0% |
| 0.50 | 21 / 0 / 0 / 15 | 100% | 0% | 21 / 0 / 0 / 15 | 100% | 0% |
| 0.60 | 21 / 0 / 0 / 15 | 100% | 0% | 21 / 0 / 0 / 15 | 100% | 0% |
| 0.70 | 21 / 0 / 0 / 15 | 100% | 0% | 21 / 0 / 0 / 15 | 100% | 0% |

## Reading the result

The current threshold 0.50 meets this RUN-A sweep's observed target, and every tested threshold from 0.40 through 0.70 ties on these 36 cases. This grid does **not** establish that 0.50 is uniquely optimal. It is a run-level integration check, not an out-of-fold evaluation or an external holdout.

The source run's raw evidence is stored locally under `results/raw/experiments/20261112T151032Z-6eea4579/`; `results/raw/` is not tracked by Git. This Markdown file records the reproduced sweep output for review.
