# G3 candidate metrics — corpus 37 case (2026-11-13)

Số liệu chính thức cho corpus 37 case (có `hpp-mal-004`), thay cho bản
[g3-candidate-metrics-20261113.md](g3-candidate-metrics-20261113.md) — bản đó là
**historical (corpus 36 case), không dùng làm kết quả cuối**.

Nguồn: RUN-A `20261113T105850Z-f4deea31` (direct: CRS-only + ML-only) và
RUN-B `20261113T110057Z-5a65730f` (hybrid); model `lr-tfidf-3cls-1.1` (artifact
`model.joblib` `14d536acfb5f4062…`). Định nghĩa giữ nguyên bản 36-case:
detected = runner `detected` (ML-only: `ml_enforcement.label` ∈ {sqli,xss});
blocked = `waf_decision=blocked` (ML-only: `ml_enforcement.decision=blocked`);
true bypass = `outcome=true_bypass` (WAF cho qua + hiệu ứng ứng dụng thật);
effect = `semantic_effect=true` trên rows malicious (không đo ở ML-only).
Hash toàn bộ run: [run-audit-37case-20261113](../gates/run-audit-37case-20261113.md).

**Bypass duy nhất của corpus:** `hpp-mal-004` — true bypass PL1–2 trên CRS-only
và hybrid; PL1–3 trên ML-only (attack score 0.276 < 0.5). Tất cả cell khác = 0.

**Đánh đổi PL3 (cả RUN-A và RUN-B): 10/15 case benign bị chặn**
— CRS-only 7/11 SQLi benign + 3/4 XSS benign; hybrid tương tự. Giá điều chỉnh
paranoia cao: block 100% malicious nhưng FPR benign tăng mạnh.

## CRS-only × `20261113T105850Z-f4deea31`

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

## ML-only × `20261113T105850Z-f4deea31`

| PL | Vuln | Technique | Malicious detected | Malicious blocked | True bypass | Malicious app effect | Benign blocked |
|---:|---|---|---:|---:|---:|---:|---:|
| 1 | sqli | case-comment | 5/5 | 5/5 | 0/5 | — | 0/3 |
| 1 | sqli | double-encoding | 4/4 | 4/4 | 0/4 | — | 0/2 |
| 1 | sqli | hpp | 3/4 | 3/4 | 1/4 | — | 0/3 |
| 1 | sqli | parsing-discrepancy | 3/3 | 3/3 | 0/3 | — | 0/3 |
| 1 | xss | case-comment | 3/3 | 3/3 | 0/3 | — | 0/0 |
| 1 | xss | double-encoding | 1/1 | 1/1 | 0/1 | — | 0/1 |
| 1 | xss | hpp | 1/1 | 1/1 | 0/1 | — | 0/1 |
| 1 | xss | parsing-discrepancy | 1/1 | 1/1 | 0/1 | — | 0/2 |
| 2 | sqli | case-comment | 5/5 | 5/5 | 0/5 | — | 0/3 |
| 2 | sqli | double-encoding | 4/4 | 4/4 | 0/4 | — | 0/2 |
| 2 | sqli | hpp | 3/4 | 3/4 | 1/4 | — | 0/3 |
| 2 | sqli | parsing-discrepancy | 3/3 | 3/3 | 0/3 | — | 0/3 |
| 2 | xss | case-comment | 3/3 | 3/3 | 0/3 | — | 0/0 |
| 2 | xss | double-encoding | 1/1 | 1/1 | 0/1 | — | 0/1 |
| 2 | xss | hpp | 1/1 | 1/1 | 0/1 | — | 0/1 |
| 2 | xss | parsing-discrepancy | 1/1 | 1/1 | 0/1 | — | 0/2 |
| 3 | sqli | case-comment | 5/5 | 5/5 | 0/5 | — | 0/3 |
| 3 | sqli | double-encoding | 4/4 | 4/4 | 0/4 | — | 0/2 |
| 3 | sqli | hpp | 3/4 | 3/4 | 0/4 | — | 0/3 |
| 3 | sqli | parsing-discrepancy | 3/3 | 3/3 | 0/3 | — | 0/3 |
| 3 | xss | case-comment | 3/3 | 3/3 | 0/3 | — | 0/0 |
| 3 | xss | double-encoding | 1/1 | 1/1 | 0/1 | — | 0/1 |
| 3 | xss | hpp | 1/1 | 1/1 | 0/1 | — | 0/1 |
| 3 | xss | parsing-discrepancy | 1/1 | 1/1 | 0/1 | — | 0/2 |

## Hybrid × `20261113T110057Z-5a65730f`

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
