# Dataset-source trial — 2026-11-15

## Scope and environment

Exploratory audit of three proposed sources for the current request-payload WAF classifier. A separate candidate was trained only from the source that was available and compatible enough to test. No baseline artifact, production service, 37-case evidence, or corpus file was modified. The candidate is not promoted.

Training used the existing v1.4 fit rows (33,118) plus 6,410 unique rows from the Multi-Class source, with the existing TF-IDF char n-gram + LogisticRegression settings. It ran in the repo's Docker image: Python 3.11, scikit-learn 1.7.1, NumPy 1.26.4, SciPy 1.13.1. New-source split: normalized text SHA-256 first-byte bucket `<51/256` as holdout; no family IDs, so the split is payload-level.

## Source audit

| Source | File-level finding | Decision |
|---|---|---|
| [Multi-Class Web Attack Dataset, v2](https://data.mendeley.com/datasets/zhzd5j9ffy/2) | Downloaded `baseline_dataset.csv` (25,736 rows; SHA-256 `d3b3509555924de6e1d37522806f2debd97ea6659e8254a95ad98d19c28a24d`). Raw labels: Normal 12,000; XSS 3,057; SQLi 3,216; CMDi 2,568; LFI 3,000; SSRF 1,895. The file has `method`, `url`, `payload`, 56 engineered features and `label`. Only Normal/XSS/SQLi were considered. Using the WAF's current query-value/body extraction left 8,475 unique usable payloads after removing 830 duplicate rows and one conflicting payload (`@`); 8,967 in-scope rows had no scoreable query/body value. After exact overlap exclusion against existing project sources, 6,410 rows entered train and 1,665 clean rows remained in holdout. | **Conditional fit; P1 trial done.** Use only raw request values, never the 56 engineered features. Its raw request data does not map fully to current WAF input, and there are no family IDs. |
| [Obfuscated XSS Dataset, v1](https://data.mendeley.com/datasets/z6xm42spk6/1) | Mendeley metadata reports 27,314 Sentence/Label rows and CC BY 4.0. However, the published file-list API returned `[]`; no archive/CSV was available to inspect or hash. The 185,694,822-byte CSV in Downloads is the *existing* XSS source used by v1.4 (SHA-256 `81648bab21a3f2859d50fa679fa2b34f54486b920c183460a3efcbbbcc43af4c`), not this DOI. | **Not file-audited; not trained.** Obtain the actual v1 archive before considering it. |
| [RbSQLi v4](https://data.mendeley.com/datasets/xz4d5zj5yw/4) | Downloaded archive SHA-256 `f0d5ef498a933ec3edd929df234a672439ae4988ad5efa8589cdea8a42a7c390` (174,509,146 bytes). Contains one 1.39-GB CSV with 10,190,450 rows and columns `sql_query`, `injection_type`, `vulnerability_status`, plus SQL structure fields. Verified labels: 7,490,880 `No` / `None_Type` and 2,699,570 `Yes` across six SQLi categories. It contains SQL statements, not HTTP request values, and no XSS class. | **Do not add directly to this model.** It can be a separate SQL-query classification experiment after label/quality review; it is not a compatible WAF request corpus. |

## Candidate results

| Holdout | v1.4 baseline | Combined trial | Reading |
|---|---:|---:|---|
| New Multi-Class clean payload holdout (1,665 rows) | Accuracy 78.50%, macro-F1 0.793, P1 binary F1 0.835 | Accuracy 97.54%, macro-F1 0.975, P1 binary F1 0.986 | Strong gain on this payload-level source split; not family-disjoint, and likely public-template overlap remains possible despite exact dedup. |
| Existing HttpParams external holdout (10,211) | Accuracy 99.951%, macro-F1 0.9960 | Accuracy 99.951%, macro-F1 0.9978 | No accuracy change; macro-F1 slightly higher. SQLi recall moved 0.99972 → 0.99917; XSS recall moved 0.97740 → 0.98870. |
| Existing XSS-source holdout (10,000) | Accuracy 99.68%, macro-F1 0.9968; benign→XSS FPR 0.02% | Accuracy 99.56%, macro-F1 0.9956; benign→XSS FPR 0.26% | Candidate has a measurable XSS/benign false-positive regression (1 → 13 benign rows). |
| 37 lab cases, offline scores only | 0 FP, 1 FN (`hpp-mal-004`) | 0 FP, 0 FN | Candidate crosses the SQLi attack-score threshold for `hpp-mal-004` (0.250 → 0.595). This is not RUN-A/RUN-B or WAF-path evidence. |

P1 policy is evaluated as `P(sqli)+P(xss) >= 0.5`; argmax class metrics are reported separately in the raw metrics file. No threshold was tuned. The model fit totals 39,528 rows: benign 18,968; SQLi 9,886; XSS 10,674.

## Decision

The Multi-Class source is promising enough for a **candidate-only follow-up**, not promotion. Before calling its gain generalization, audit near-duplicates/families or get a family-disjoint holdout; then run RUN-A/RUN-B with the candidate and retain CRS, app-effect, and browser evidence. Its XSS holdout regression also needs review under existing acceptance criteria.

RbSQLi should remain outside the main request-payload training set. The Obfuscated XSS source cannot be assessed until its actual file is obtainable. No service configuration changed; docker-compose still defaults to v1.1. Locked v1.4/v1.5 artifacts are unchanged.

## Reproducibility files

- Candidate model and complete JSON metrics: `temp/candidate-source-trial-20261115/` (ignored local experiment output).
- Driver/audit scripts: `temp/candidate_source_trial_20261115.py`, `temp/audit_trial_holdouts_20261115.py` (ignored, one-off scripts).
- Downloaded sources: `dataset/raw/candidate-sources-20261115/` (ignored raw data).

