# CRS Paranoia Level 1→3 — backend thật (Flask/PyMySQL/MySQL), run mới giữa kỳ

Run: `20261025T172523Z-cecdfdeb` (26/10/2026 00:25 giờ VN) — dùng lệnh
`python waf-crs/run_integrated_smoke.py --levels 1 2 3` sau khi đã tích hợp
ML-WAF v0. Corpus smoke 6 case (3 benign + 3 SQLi) × 3 PL; direct controls
được validate cho từng case; raw evidence kèm `results.json/csv`, audit + app
snapshots, effective configs, image IDs.

## Kết quả nhất quán với run tích hợp 18/10

| PL | SQLi detected | SQLi blocked | SQLi tới app | True bypass | Benign blocked | Blocking FPR | Latency round-trip (ms) |
|---|---|---|---|---|---|---|---|
| 1 | 3/3 (100%) | 3/3 (100%) | 0/3 | 0/3 (0%) | 0/3 | **0.0%** | 4–35 |
| 2 | 3/3 (100%) | 3/3 (100%) | 0/3 | 0/3 (0%) | 0/3 | **0.0%** | 4–35 |
| 3 | 3/3 (100%) | 3/3 (100%) | 0/3 | 0/3 (0%) | 1/3 | **33.3%** | 4–35 |

### FP duy nhất ở PL3 (bằng chứng audit)

| Case | Input benign | Rule | Nội dung match |
|---|---|---|---|
| BEN-PRODUCT | `/product?id=1` (giá trị chỉ là số 1) | `932350` | **tên tham số** `id` match lệnh Unix `id` trong `ARGS_NAMES:id`, sau đó `949110` chặn · HTTP 403 |

## Sau run, stack quay về PL1 (không thay đổi threshold — nguyên tắc đo trung thực)

```powershell
$env:CRS_PL = '1'; docker compose up -d --wait
```

## Diễn giải — dùng cho slide hardening

1. PL tăng → tập rule nhiều hơn nhưng **chưa tăng detection vì corpus đã bị PL1
   bắt 100%**; do đó PL chỉ thêm hành vi FP.
2. FP PL3 không đến từ giá trị mà từ **tên tham số** — khuyến nghị exception
   phải hẹp theo endpoint/parameter (vd exemption cho rule `932350` trên
   `ARGS_NAMES:id` của `/product`), KHÔNG nới threshold chung.
3. So sánh CRS (100%/FPR 0% PL1) vs ML-WAF v0 (recall 85%, FPR 1.7%) chi tiết
   ở `results/tables/ml-v0-summary.md` — CẢ HAI đều chạy cùng oracle nhưng đo
   ở tầng khác nhau: CRS = end-to-end chặn; ML = classifier scoring (chưa chặn).
   Sau giữa kỳ có proxy enforcement để so cùng một chiều.
