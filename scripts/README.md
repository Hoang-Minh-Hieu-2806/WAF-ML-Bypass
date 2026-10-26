# scripts/ — Tự động hóa & Đánh giá (owner: Huỳnh Như Hoàng)

Giao thức và schema đã chốt tại [docs/interfaces.md](../docs/interfaces.md) (Hiếu chốt interface,
Hoàng implement). Thay đổi contract phải qua review nhóm.

## Nội dung hiện có

- `run_experiment.py` — đọc `dataset/bypass/<technique>/*.json`
  (schema mục 1 của interfaces.md, `params`/`form` là danh sách cặp có thứ tự),
  gửi y nguyên request qua CRS (`127.0.0.1:8081`), direct control (`127.0.0.1:8080`),
  và ML enforcement (`127.0.0.1:8082`); ghi `results/raw/experiments/<run-id>/`
  gồm quyết định/block/bypass/FPR riêng cho CRS và ML, app behavior, rule ID,
  model score/version, latency và evidence JSON/CSV.
- `requirements-attack.txt` — dependency tool tấn công (sqlmap, WAF-A-MoLE), cài cục bộ,
  KHÔNG đưa vào image compose.
- `sweep_thresholds.py` — đọc một `results.json`, deduplicate theo case ID và
  in bảng precision/recall/F1/FPR theo threshold mà không sửa raw evidence.
