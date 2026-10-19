# scripts/ — Tự động hóa & Đánh giá (owner: Huỳnh Như Hoàng)

Giao thức và schema đã chốt tại [docs/interfaces.md](../docs/interfaces.md) (Hiếu chốt interface,
Hoàng implement). Thay đổi contract phải qua review nhóm.

## Nội dung dự kiến

- `run_experiment.py` — **chưa implement**. Contract: đọc `dataset/bypass/<technique>/*.json`
  (schema mục 1 của interfaces.md, `params`/`form` là danh sách cặp có thứ tự),
  gửi y nguyên request qua CRS (`127.0.0.1:8081`), direct control (`127.0.0.1:8080`),
  gọi ML `/score` (`127.0.0.1:8082`); ghi `results/raw/<run-id>/` gồm
  `waf decision, http status, app behavior, rule id, ml {label,score}` (CSV + JSON).
- `requirements-attack.txt` — dependency tool tấn công (sqlmap, WAF-A-MoLE), cài cục bộ,
  KHÔNG đưa vào image compose.
