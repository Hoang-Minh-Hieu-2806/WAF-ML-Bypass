# G3 candidate metrics - v1.4, corpus 37 case (2026-11-14)

Candidate integration matrix for model `lr-tfidf-3cls-1.4`. This supplements, and does not replace, the locked v1.1 baseline at [g3-candidate-metrics-37case-20261113](g3-candidate-metrics-37case-20261113.md). The corpus and locked baseline evidence are unchanged.

| Run | Mode | Run ID | Results SHA-256 | Rows | Pending / incomplete / invalid |
|---|---|---|---|---:|---|
| RUN-A | CRS direct + standalone ML | `20261114T112812Z-1f47c60b` | `ca434bb30cc6e95b62a776ca9046a93d5c3fe31a7493dcc2684d7d612d6f416e` | 111 | 0 / 0 / 0 |
| RUN-B | CRS -> ML hybrid | `20261114T113212Z-ee819911` | `a142fb3b90d6ef47c822ed295155bfd48e778a089acded0876fe5c92d429a561` | 111 | 0 / 0 / 0 |

Definitions match the v1.1 table: detected uses runner `detected` (ML-only uses `ml_enforcement.label` in `{sqli,xss}`); blocked uses the effective decision for that path; true bypass uses the path's `true_bypass`; app effect is `semantic_effect=true` on malicious rows. Standalone ML app effect IS measured in `plN-app.json` (`-ml` suffixed entries); the matrix shows `n/a` only because `results.json` does not join app evidence for the ML-only path — check `plN-app.json` directly for ML-only cells. Benign denominators include only benign corpus rows in each PL x vulnerability x technique cell.

RUN-A's CRS-only and ML-only matrices are separate views of the same 111 case-rounds. RUN-B records the hybrid path. RUN-B used the updated `pass_without_effect` outcome, so do not compare its outcome labels directly with v1.1 locked evidence. The matrix reports observed block/effect fields and keeps detection, block, bypass, and effect distinct.

## CRS-only - RUN-A `20261114T112812Z-1f47c60b`

| PL | Vuln | Technique | Malicious detected | Malicious blocked | True bypass | Malicious app effect | Benign blocked |
|---:|---|---|---:|---:|---:|---:|---:|
| 1 | sqli | case-comment | 5/5 | 5/5 | 0/5 | 0/5 | 0/3 |
| 1 | sqli | double-encoding | 2/4 | 2/4 | 0/4 | 0/4 | 0/2 |
| 1 | sqli | hpp | 3/4 | 3/4 | 1/4 | 1/4 | 0/3 |
| 1 | sqli | parsing-discrepancy | 2/3 | 3/3 | 0/3 | 0/3 | 0/3 |
| 1 | xss | case-comment | 3/3 | 3/3 | 0/3 | 0/3 | 0/0 |
| 1 | xss | double-encoding | 0/1 | 0/1 | 0/1 | 0/1 | 0/1 |
| 1 | xss | hpp | 1/1 | 1/1 | 0/1 | 0/1 | 0/1 |
| 1 | xss | parsing-discrepancy | 1/1 | 1/1 | 0/1 | 0/1 | 0/2 |
| 2 | sqli | case-comment | 5/5 | 5/5 | 0/5 | 0/5 | 0/3 |
| 2 | sqli | double-encoding | 2/4 | 2/4 | 0/4 | 0/4 | 0/2 |
| 2 | sqli | hpp | 3/4 | 3/4 | 1/4 | 1/4 | 0/3 |
| 2 | sqli | parsing-discrepancy | 2/3 | 3/3 | 0/3 | 0/3 | 0/3 |
| 2 | xss | case-comment | 3/3 | 3/3 | 0/3 | 0/3 | 0/0 |
| 2 | xss | double-encoding | 0/1 | 0/1 | 0/1 | 0/1 | 0/1 |
| 2 | xss | hpp | 1/1 | 1/1 | 0/1 | 0/1 | 0/1 |
| 2 | xss | parsing-discrepancy | 1/1 | 1/1 | 0/1 | 0/1 | 1/2 |
| 3 | sqli | case-comment | 5/5 | 5/5 | 0/5 | 0/5 | 1/3 |
| 3 | sqli | double-encoding | 2/4 | 4/4 | 0/4 | 0/4 | 2/2 |
| 3 | sqli | hpp | 3/4 | 4/4 | 0/4 | 0/4 | 3/3 |
| 3 | sqli | parsing-discrepancy | 2/3 | 3/3 | 0/3 | 0/3 | 1/3 |
| 3 | xss | case-comment | 3/3 | 3/3 | 0/3 | 0/3 | 0/0 |
| 3 | xss | double-encoding | 1/1 | 1/1 | 0/1 | 0/1 | 1/1 |
| 3 | xss | hpp | 1/1 | 1/1 | 0/1 | 0/1 | 1/1 |
| 3 | xss | parsing-discrepancy | 1/1 | 1/1 | 0/1 | 0/1 | 1/2 |

## ML-only - RUN-A `20261114T112812Z-1f47c60b`

| PL | Vuln | Technique | Malicious detected | Malicious blocked | True bypass | Malicious app effect | Benign blocked |
|---:|---|---|---:|---:|---:|---:|---:|
| 1 | sqli | case-comment | 5/5 | 5/5 | 0/5 | n/a | 0/3 |
| 1 | sqli | double-encoding | 4/4 | 4/4 | 0/4 | n/a | 0/2 |
| 1 | sqli | hpp | 3/4 | 3/4 | 1/4 | n/a | 0/3 |
| 1 | sqli | parsing-discrepancy | 2/3 | 3/3 | 0/3 | n/a | 0/3 |
| 1 | xss | case-comment | 3/3 | 3/3 | 0/3 | n/a | 0/0 |
| 1 | xss | double-encoding | 1/1 | 1/1 | 0/1 | n/a | 0/1 |
| 1 | xss | hpp | 1/1 | 1/1 | 0/1 | n/a | 0/1 |
| 1 | xss | parsing-discrepancy | 1/1 | 1/1 | 0/1 | n/a | 0/2 |
| 2 | sqli | case-comment | 5/5 | 5/5 | 0/5 | n/a | 0/3 |
| 2 | sqli | double-encoding | 4/4 | 4/4 | 0/4 | n/a | 0/2 |
| 2 | sqli | hpp | 3/4 | 3/4 | 1/4 | n/a | 0/3 |
| 2 | sqli | parsing-discrepancy | 2/3 | 3/3 | 0/3 | n/a | 0/3 |
| 2 | xss | case-comment | 3/3 | 3/3 | 0/3 | n/a | 0/0 |
| 2 | xss | double-encoding | 1/1 | 1/1 | 0/1 | n/a | 0/1 |
| 2 | xss | hpp | 1/1 | 1/1 | 0/1 | n/a | 0/1 |
| 2 | xss | parsing-discrepancy | 1/1 | 1/1 | 0/1 | n/a | 0/2 |
| 3 | sqli | case-comment | 5/5 | 5/5 | 0/5 | n/a | 0/3 |
| 3 | sqli | double-encoding | 4/4 | 4/4 | 0/4 | n/a | 0/2 |
| 3 | sqli | hpp | 3/4 | 3/4 | 1/4 | n/a | 0/3 |
| 3 | sqli | parsing-discrepancy | 2/3 | 3/3 | 0/3 | n/a | 0/3 |
| 3 | xss | case-comment | 3/3 | 3/3 | 0/3 | n/a | 0/0 |
| 3 | xss | double-encoding | 1/1 | 1/1 | 0/1 | n/a | 0/1 |
| 3 | xss | hpp | 1/1 | 1/1 | 0/1 | n/a | 0/1 |
| 3 | xss | parsing-discrepancy | 1/1 | 1/1 | 0/1 | n/a | 0/2 |

## Hybrid - RUN-B `20261114T113212Z-ee819911`

| PL | Vuln | Technique | Malicious detected | Malicious blocked | True bypass | Malicious app effect | Benign blocked |
|---:|---|---|---:|---:|---:|---:|---:|
| 1 | sqli | case-comment | 5/5 | 5/5 | 0/5 | 0/5 | 0/3 |
| 1 | sqli | double-encoding | 2/4 | 4/4 | 0/4 | 0/4 | 0/2 |
| 1 | sqli | hpp | 3/4 | 3/4 | 1/4 | 1/4 | 0/3 |
| 1 | sqli | parsing-discrepancy | 2/3 | 3/3 | 0/3 | 0/3 | 0/3 |
| 1 | xss | case-comment | 3/3 | 3/3 | 0/3 | 0/3 | 0/0 |
| 1 | xss | double-encoding | 0/1 | 1/1 | 0/1 | 0/1 | 0/1 |
| 1 | xss | hpp | 1/1 | 1/1 | 0/1 | 0/1 | 0/1 |
| 1 | xss | parsing-discrepancy | 1/1 | 1/1 | 0/1 | 0/1 | 0/2 |
| 2 | sqli | case-comment | 5/5 | 5/5 | 0/5 | 0/5 | 0/3 |
| 2 | sqli | double-encoding | 2/4 | 4/4 | 0/4 | 0/4 | 0/2 |
| 2 | sqli | hpp | 3/4 | 3/4 | 1/4 | 1/4 | 0/3 |
| 2 | sqli | parsing-discrepancy | 2/3 | 3/3 | 0/3 | 0/3 | 0/3 |
| 2 | xss | case-comment | 3/3 | 3/3 | 0/3 | 0/3 | 0/0 |
| 2 | xss | double-encoding | 0/1 | 1/1 | 0/1 | 0/1 | 0/1 |
| 2 | xss | hpp | 1/1 | 1/1 | 0/1 | 0/1 | 0/1 |
| 2 | xss | parsing-discrepancy | 1/1 | 1/1 | 0/1 | 0/1 | 1/2 |
| 3 | sqli | case-comment | 5/5 | 5/5 | 0/5 | 0/5 | 1/3 |
| 3 | sqli | double-encoding | 2/4 | 4/4 | 0/4 | 0/4 | 2/2 |
| 3 | sqli | hpp | 3/4 | 4/4 | 0/4 | 0/4 | 3/3 |
| 3 | sqli | parsing-discrepancy | 2/3 | 3/3 | 0/3 | 0/3 | 1/3 |
| 3 | xss | case-comment | 3/3 | 3/3 | 0/3 | 0/3 | 0/0 |
| 3 | xss | double-encoding | 1/1 | 1/1 | 0/1 | 0/1 | 1/1 |
| 3 | xss | hpp | 1/1 | 1/1 | 0/1 | 0/1 | 1/1 |
| 3 | xss | parsing-discrepancy | 1/1 | 1/1 | 0/1 | 0/1 | 1/2 |
