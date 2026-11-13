# G3 candidate metrics by vulnerability, technique, configuration, and PL

These tables use the post-G2 CRS hardening candidate runs. CRS-only and ML-only rows come from RUN-A `20261112T171730Z-efb04f02`; hybrid rows come from RUN-B `20261112T171923Z-0a05d016`. Each row is a case-round at one PL. The R7 replay correction does not change the row outcome, WAF decision, detection, blocking, or effect fields; it adds exact-header execution evidence for the existing XSS double-encoding pending case.

For CRS-only and hybrid, detection uses the runner `detected` field, blocking uses `waf_decision=blocked`, and effect counts malicious rows with `semantic_effect=true`. For ML-only, detection uses the model predicted class (`ml_enforcement.label` in `{sqli,xss}`) and blocking uses `ml_enforcement.decision=blocked`; app effect is not measured on the standalone ML endpoint. Benign blocked is computed from each configuration’s decision. A slash shows count/total.

## CRS-only × `20261112T171730Z-efb04f02`

| PL | Vuln | Technique | Malicious detected | Malicious blocked | True bypass | Malicious app effect | Benign blocked |
|---:|---|---|---:|---:|---:|---:|---:|
| 1 | sqli | case-comment | 5/5 | 5/5 | 0/5 | 0/5 | 0/3 |
| 1 | sqli | double-encoding | 2/4 | 2/4 | 0/4 | 0/4 | 0/2 |
| 1 | sqli | hpp | 3/3 | 3/3 | 0/3 | 0/3 | 0/3 |
| 1 | sqli | parsing-discrepancy | 2/3 | 3/3 | 0/3 | 0/3 | 0/3 |
| 1 | xss | case-comment | 3/3 | 3/3 | 0/3 | 0/3 | 0/0 |
| 1 | xss | double-encoding | 0/1 | 0/1 | 0/1 | 0/1 | 0/1 |
| 1 | xss | hpp | 1/1 | 1/1 | 0/1 | 0/1 | 0/1 |
| 1 | xss | parsing-discrepancy | 1/1 | 1/1 | 0/1 | 0/1 | 0/2 |
| 2 | sqli | case-comment | 5/5 | 5/5 | 0/5 | 0/5 | 0/3 |
| 2 | sqli | double-encoding | 2/4 | 2/4 | 0/4 | 0/4 | 0/2 |
| 2 | sqli | hpp | 3/3 | 3/3 | 0/3 | 0/3 | 0/3 |
| 2 | sqli | parsing-discrepancy | 2/3 | 3/3 | 0/3 | 0/3 | 0/3 |
| 2 | xss | case-comment | 3/3 | 3/3 | 0/3 | 0/3 | 0/0 |
| 2 | xss | double-encoding | 0/1 | 0/1 | 0/1 | 0/1 | 0/1 |
| 2 | xss | hpp | 1/1 | 1/1 | 0/1 | 0/1 | 0/1 |
| 2 | xss | parsing-discrepancy | 1/1 | 1/1 | 0/1 | 0/1 | 1/2 |
| 3 | sqli | case-comment | 5/5 | 5/5 | 0/5 | 0/5 | 1/3 |
| 3 | sqli | double-encoding | 2/4 | 4/4 | 0/4 | 0/4 | 2/2 |
| 3 | sqli | hpp | 3/3 | 3/3 | 0/3 | 0/3 | 3/3 |
| 3 | sqli | parsing-discrepancy | 2/3 | 3/3 | 0/3 | 0/3 | 1/3 |
| 3 | xss | case-comment | 3/3 | 3/3 | 0/3 | 0/3 | 0/0 |
| 3 | xss | double-encoding | 1/1 | 1/1 | 0/1 | 0/1 | 1/1 |
| 3 | xss | hpp | 1/1 | 1/1 | 0/1 | 0/1 | 1/1 |
| 3 | xss | parsing-discrepancy | 1/1 | 1/1 | 0/1 | 0/1 | 1/2 |

## ML-only × `20261112T171730Z-efb04f02`

| PL | Vuln | Technique | Malicious detected | Malicious blocked | True bypass | Malicious app effect | Benign blocked |
|---:|---|---|---:|---:|---:|---:|---:|
| 1 | sqli | case-comment | 5/5 | 5/5 | 0/5 | — | 0/3 |
| 1 | sqli | double-encoding | 4/4 | 4/4 | 0/4 | — | 0/2 |
| 1 | sqli | hpp | 3/3 | 3/3 | 0/3 | — | 0/3 |
| 1 | sqli | parsing-discrepancy | 3/3 | 3/3 | 0/3 | — | 0/3 |
| 1 | xss | case-comment | 3/3 | 3/3 | 0/3 | — | 0/0 |
| 1 | xss | double-encoding | 1/1 | 1/1 | 0/1 | — | 0/1 |
| 1 | xss | hpp | 1/1 | 1/1 | 0/1 | — | 0/1 |
| 1 | xss | parsing-discrepancy | 1/1 | 1/1 | 0/1 | — | 0/2 |
| 2 | sqli | case-comment | 5/5 | 5/5 | 0/5 | — | 0/3 |
| 2 | sqli | double-encoding | 4/4 | 4/4 | 0/4 | — | 0/2 |
| 2 | sqli | hpp | 3/3 | 3/3 | 0/3 | — | 0/3 |
| 2 | sqli | parsing-discrepancy | 3/3 | 3/3 | 0/3 | — | 0/3 |
| 2 | xss | case-comment | 3/3 | 3/3 | 0/3 | — | 0/0 |
| 2 | xss | double-encoding | 1/1 | 1/1 | 0/1 | — | 0/1 |
| 2 | xss | hpp | 1/1 | 1/1 | 0/1 | — | 0/1 |
| 2 | xss | parsing-discrepancy | 1/1 | 1/1 | 0/1 | — | 0/2 |
| 3 | sqli | case-comment | 5/5 | 5/5 | 0/5 | — | 0/3 |
| 3 | sqli | double-encoding | 4/4 | 4/4 | 0/4 | — | 0/2 |
| 3 | sqli | hpp | 3/3 | 3/3 | 0/3 | — | 0/3 |
| 3 | sqli | parsing-discrepancy | 3/3 | 3/3 | 0/3 | — | 0/3 |
| 3 | xss | case-comment | 3/3 | 3/3 | 0/3 | — | 0/0 |
| 3 | xss | double-encoding | 1/1 | 1/1 | 0/1 | — | 0/1 |
| 3 | xss | hpp | 1/1 | 1/1 | 0/1 | — | 0/1 |
| 3 | xss | parsing-discrepancy | 1/1 | 1/1 | 0/1 | — | 0/2 |

## Hybrid × `20261112T171923Z-0a05d016`

| PL | Vuln | Technique | Malicious detected | Malicious blocked | True bypass | Malicious app effect | Benign blocked |
|---:|---|---|---:|---:|---:|---:|---:|
| 1 | sqli | case-comment | 5/5 | 5/5 | 0/5 | 0/5 | 0/3 |
| 1 | sqli | double-encoding | 2/4 | 4/4 | 0/4 | 0/4 | 0/2 |
| 1 | sqli | hpp | 3/3 | 3/3 | 0/3 | 0/3 | 0/3 |
| 1 | sqli | parsing-discrepancy | 2/3 | 3/3 | 0/3 | 0/3 | 0/3 |
| 1 | xss | case-comment | 3/3 | 3/3 | 0/3 | 0/3 | 0/0 |
| 1 | xss | double-encoding | 0/1 | 1/1 | 0/1 | 0/1 | 0/1 |
| 1 | xss | hpp | 1/1 | 1/1 | 0/1 | 0/1 | 0/1 |
| 1 | xss | parsing-discrepancy | 1/1 | 1/1 | 0/1 | 0/1 | 0/2 |
| 2 | sqli | case-comment | 5/5 | 5/5 | 0/5 | 0/5 | 0/3 |
| 2 | sqli | double-encoding | 2/4 | 4/4 | 0/4 | 0/4 | 0/2 |
| 2 | sqli | hpp | 3/3 | 3/3 | 0/3 | 0/3 | 0/3 |
| 2 | sqli | parsing-discrepancy | 2/3 | 3/3 | 0/3 | 0/3 | 0/3 |
| 2 | xss | case-comment | 3/3 | 3/3 | 0/3 | 0/3 | 0/0 |
| 2 | xss | double-encoding | 0/1 | 1/1 | 0/1 | 0/1 | 0/1 |
| 2 | xss | hpp | 1/1 | 1/1 | 0/1 | 0/1 | 0/1 |
| 2 | xss | parsing-discrepancy | 1/1 | 1/1 | 0/1 | 0/1 | 1/2 |
| 3 | sqli | case-comment | 5/5 | 5/5 | 0/5 | 0/5 | 1/3 |
| 3 | sqli | double-encoding | 2/4 | 4/4 | 0/4 | 0/4 | 2/2 |
| 3 | sqli | hpp | 3/3 | 3/3 | 0/3 | 0/3 | 3/3 |
| 3 | sqli | parsing-discrepancy | 2/3 | 3/3 | 0/3 | 0/3 | 1/3 |
| 3 | xss | case-comment | 3/3 | 3/3 | 0/3 | 0/3 | 0/0 |
| 3 | xss | double-encoding | 1/1 | 1/1 | 0/1 | 0/1 | 1/1 |
| 3 | xss | hpp | 1/1 | 1/1 | 0/1 | 0/1 | 1/1 |
| 3 | xss | parsing-discrepancy | 1/1 | 1/1 | 0/1 | 0/1 | 1/2 |
