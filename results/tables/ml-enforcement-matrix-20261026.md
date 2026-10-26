# ML enforcement + hybrid matrix (26/10/2026)

Authoritative runs:

- CRS-only + ML-only: `20261026T064734Z-810f2452`.
- Hybrid `CRS -> ML -> web-app`: `20261026T064820Z-1397133d`.
- Corpus: 26 cases (15 malicious, 11 benign) × PL1–3; mỗi run 78 lượt.
- Cả hai run: `incomplete=0`, `control_invalid_total=0`, true bypass 0/15.

## End-to-end outcomes

| Path | PL1 malicious blocked / FPR | PL2 malicious blocked / FPR | PL3 malicious blocked / FPR |
|---|---:|---:|---:|
| CRS-only | 13/15 (86.7%) / 1/11 (9.1%) | 13/15 (86.7%) / 1/11 (9.1%) | 15/15 / 8/11 (72.7%) |
| ML-only, threshold 0.5 | 15/15 / 0/11 | 15/15 / 0/11 | 15/15 / 0/11 |
| Hybrid CRS→ML | 15/15 / 1/11 (9.1%) | 15/15 / 1/11 (9.1%) | 15/15 / 8/11 (72.7%) |

CRS SQL-family detection giữ nguyên 11/15 = 73.3% ở mọi PL. Hai case
`de-mal-002/003` được CRS-only cho qua mà không có semantic effect. Trong hybrid
PL1–2, CRS không phát rule cho hai case này nhưng ML chặn với score 0.6295 và
0.6184; evidence ghi `blocking_layer="ml"`. Ở PL3, CRS tự block hai case bằng
protocol rules nhưng FPR tăng lên 72.7%; hybrid không sửa được false positive
do lớp CRS phía trước tạo ra.

## Latency của run PL1

| Path | Median (ms) | p95 (ms) |
|---|---:|---:|
| CRS-only | 13.953 | 33.823 |
| ML-only | 17.181 | 37.708 |
| Hybrid CRS→ML | 14.729 | 56.402 |

Các số latency là một lượt 26 case trên máy lab, chỉ dùng mô tả run; chưa phải
benchmark tải hoặc so sánh có ý nghĩa thống kê.

## Threshold sweep trên cùng 26 case

| Threshold | TP | FP | Precision | Recall | F1 | FPR |
|---:|---:|---:|---:|---:|---:|---:|
| 0.30 | 15 | 1 | 93.75% | 100% | 96.77% | 9.09% |
| 0.50 | 15 | 0 | 100% | 100% | 100% | 0% |
| 0.60 | 13 | 0 | 100% | 86.67% | 92.86% | 0% |
| 0.80 | 8 | 0 | 100% | 53.33% | 69.56% | 0% |

Threshold 0.5 tốt nhất trên corpus nhỏ này nhưng chưa được coi là threshold
production. Kết quả synthetic không thay thế external holdout.

```powershell
python scripts/sweep_thresholds.py results/raw/experiments/<run-id>/results.json
```
