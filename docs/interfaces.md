# Interfaces — hợp đồng tích hợp (Hiếu chốt, cả team tuân thủ)

> Thay đổi 3 contract dưới đây phải qua review nhóm. Cấm sửa chồng lấp sai thư mục sở hữu.

## 1. Test-case JSON (Long sở hữu payload, Hoàng auto chạy)

`dataset/bypass/<technique>/*.json`, `experiments/<technique>/` đọc cùng schema:

```json
{
  "id": "hpp-001",
  "technique": "hpp | double-encoding | case-comment | parsing-discrepancy",
  "method": "GET",
  "path": "/search",
  "params": {"q": "' OR 1=1--"},
  "headers": {},
  "expected_app": "executed | blocked",
  "note": "WAF thấy gì vs App thực thi gì"
}
```

`scripts/run_experiment.py` (Hoàng) phải gửi y nguyên `method/path/params/headers`,
ghi `results/raw/*.csv|json` gồm: `waf decision, http status, app behavior, rule id, ml {label,score}`.

## 2. Log format (so audit.log vs app log)

* `web-app`: giữ stdout `TIMESTAMP [web-app] METHOD /path ...` và `SQL: ...`;
  thêm JSONL tại `logs/application/integrated/app.jsonl` với `case_id`,
  raw target/body, parsed pairs, SQL, observed/reference row IDs, `sql_error`,
  `semantic_effect`, HTTP status. Client truyền `X-Lab-Case-ID`; direct control
  có hậu tố `-direct`. `/healthz` kiểm tra DB, không ghi vào corpus log.
* `waf-crs` (Huy): JSON audit tại `logs/waf/integrated/audit.log`;
  blocking cần HTTP 403 + rule `949110` + không có app record tương ứng.
  SQLi detection dùng `942xxx`; rule match khác với quyết định chặn.
* Mỗi experiment phải đối chiếu được: `request -> CRS decision -> ML decision -> app behavior`.

## 3. ML scoring API (Hoàng ML implement, Hiếu deploy)

```text
POST http://waf-ml:5001/score        (nội bộ)
POST http://localhost:8082/score    (từ host)
Content-Type: application/json
{"text": "<raw query/payload>"}
->
{"label": "benign|malicious", "score": 0.0-1.0, "model_version": "stub-0.1 | lr-tfidf-1.0"}
GET /health -> {"status":"ok","model_version":"..."}
```

Stub hiện tại dùng regex (`union/select/or 1=1/--/#/script`) để trả nhãn.
Tuần 05-06 thay bằng `TF-IDF + LogisticRegression/SVM`, giữ nguyên JSON keys.

## 4. Ranh giới thư mục

* Hiếu: `docker-compose.yml`, `docker/*/Dockerfile`, `docker/db/init/`, `.env.example`, `docs/*`.
* Huy: `waf-crs/` (rule, `crs-setup.conf`, PL1-3).
* Hoàng ML: `waf-ml/app.py`, `waf-ml/requirements.txt`, `dataset/raw|processed/`.
* Long: `dataset/bypass/`, `experiments/`.
* Hoàng auto: `scripts/run_experiment.py`, `results/`.
* Tool tấn công (`WAF-A-MoLE`, `sqlmap`) chỉ ở `scripts/requirements-attack.txt`, không vào compose.

## 5. CRS baseline và smoke corpus

Runner CRS dùng `request.method/path/params/form`; `params` và `form` là danh
sách cặp theo thứ tự, bảo toàn duplicate keys. Schema ví dụ ở mục 1 là giao
diện dự kiến của runner nhóm; cần adapter nếu đọc corpus CRS, không ép danh
sách cặp thành JSON object khi thử HPP. Runner nhóm chưa được implement ở đây.

`semantic_effect` trên MySQL là có user ID ngoài kết quả query bind-parameter
tham chiếu trên cùng connection. SQL error/echo/HTTP 200 không đủ chứng minh
bypass. True bypass của CRS dùng tiêu chí được cho qua + không có SQLi detection
+ semantic effect. Lưu riêng detected/blocked/reached/effect để có thể báo thêm
tiêu chí blocking-based nếu định nghĩa rõ.
