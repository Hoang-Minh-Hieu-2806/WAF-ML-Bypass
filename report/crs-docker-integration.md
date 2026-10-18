# CRS + feature/docker — kết quả tích hợp

Đã thực thi trên lab local ngày 18/10/2026, run
`20261018T163246Z-805c4d26` (23:32:46 giờ Việt Nam).

## Phạm vi và nguồn

Checkpoint CRS trước merge: commit `a25991a` trên `feature/crs`.
Tích hợp `origin/feature/docker` tại `0c1397136e15871eb5d04a6d3472fa719e182f94`,
bao gồm các commit main/dev trước đó. Hai xung đột README và Dockerfile CRS
được xử lý bằng cách giữ Quick Start cho cả hai lab và image CRS ghim digest.

Câu hỏi: cấu hình CRS blocking/PL/audit có hoạt động trên backend Flask/MySQL,
và có đủ bằng chứng nối quyết định WAF với hành vi ứng dụng không?
Kỳ vọng trước chạy: benign qua WAF ở PL1, SQLi bị chặn; direct controls SQLi
phải tạo hiệu ứng. Chỉ các quan sát bên dưới là kết quả đã đo.

## Thiết kế

Corpus `waf-crs/integrated-smoke.json`: 3 benign + 3 SQLi (search, product,
login). Biến độc lập: blocking/detection PL cùng tăng 1→2→3. Ngưỡng inbound
5, image CRS, backend, seed DB và corpus giữ nguyên. Không sampling/random
seed; UUID chỉ dùng correlation ID. Tổng 18 request qua WAF + 18 direct
controls, healthchecks không tính vào mẫu số.

SQLi detection cần `942xxx`. Blocking cần HTTP 403 + `949110` và không có
app record cùng ID. Semantic effect là handler trả user ID ngoài tập kết quả
của query bind-parameter tham chiếu trên cùng DB connection. True bypass cần
malicious allowed + không có SQLi detection + app xác nhận semantic effect.
SQL error hoặc HTTP 200 không đủ điều kiện. Direct control không tính bypass.

## Runtime quan sát

| Thành phần | Version |
|---|---|
| Docker Engine / Compose | 29.5.3 / 5.1.4 |
| ModSecurity / connector | 3.0.17 / 1.0.4 |
| OWASP CRS | 4.30.0 |
| Backend Python | 3.11.17 |
| Flask / Werkzeug / PyMySQL | 3.1.3 / 3.1.9 / 1.2.0 |
| MySQL | 8.4.11 |

CRS dùng cùng digest với baseline SQLite; metadata giữ image IDs của stack,
version runtime, corpus/source SHA-256. Effective configs xác nhận engine On,
blocking/detection PL đúng 1/2/3 và inbound threshold 5. Không xuất container
.env/environment có mật khẩu vào evidence.

## Kết quả

| PL | SQLi detected | SQLi blocked | SQLi đến app | True bypass | Benign blocked | Blocking FPR |
|---|---:|---:|---:|---:|---:|---:|
| 1 | 3/3 | 3/3 | 0/3 | 0/3 | 0/3 | 0% |
| 2 | 3/3 | 3/3 | 0/3 | 0/3 | 0/3 | 0% |
| 3 | 3/3 | 3/3 | 0/3 | 0/3 | 1/3 | 33.333% |

Tất cả direct controls có semantic effect đúng với nhãn, không SQL error.
PL3 chặn BEN-PRODUCT (`/product?id=1`) bằng rule `932350`, sau đó `949110`.
Đây là false positive trên tên tham số `id`, không phải SQLi trong giá trị 1.
Giữ anomaly threshold 5; chưa thêm exception.

ML `/health` hoạt động; `/score` trả benign/0.1 cho `test`, malicious/0.9 cho
`1 OR 1=1`, model_version `stub-0.1`. Chỉ xác nhận contract của regex stub,
không phải kết quả huấn luyện hoặc đánh giá ML-WAF.

## Evidence và tái lập

Raw evidence: `results/raw/crs-integrated/20261018T163246Z-805c4d26/`:
metadata, effective configs, audit/app/response snapshots từng PL,
results JSON/CSV, summary và `ml-stub-smoke.json`. Raw outputs không commit.

```powershell
docker compose up -d --build --wait --wait-timeout 240
python waf-crs/run_integrated_smoke.py --levels 1 2 3
```

5 regression tests CRS và 5 tests application evidence đều pass. Application
tests dùng DB mock; smoke run dùng MySQL thật. Compose config của cả hai lab
hợp lệ. Sau chạy, stack tích hợp được đưa về PL1; cả 4 service integrated và
2 service lab SQLite đều healthy.

## Bảo toàn và giới hạn

105 file kết quả cũ trong `results/raw/crs/` được kiểm tra SHA-256 không đổi;
log cũ giữ nguyên nội dung trước merge (audit đang chạy có thể append healthchecks).
7 file code/config của lab cũ không thay đổi: hai Dockerfile, compose, corpus,
runner, backend và tests. Có ZIP source/evidence + manifest SHA-256 riêng ngoài
repo trước khi merge. Git checkpoint giữ code trước tích hợp.

Smoke corpus nhỏ, khác corpus SQLite; không gộp hai backend/corpus vào cùng
bảng metric và không kết luận PL tối ưu từ kết quả này. Oracle chỉ kiểm chứng
mở rộng kết quả SELECT/vượt xác thực; chưa bao phủ blind SQLi, mutation, tải
hoặc latency benchmark. ML vẫn là stub. Tags MySQL/Python và dependency
transitive có thể thay đổi; cần image/version metadata của từng run khi tái lập.

Dừng stack bằng `docker compose down` giữ volume DB và log bind mounts.
Khởi động lại bằng `up -d --wait` với CRS_PL=1; không dùng `down -v` để rollback.
