# Architecture — lab tích hợp CRS

Lab local gồm bốn service từ `feature/docker` và module CRS đã tích hợp:

```text
Client -> 127.0.0.1:8081 -> waf-crs:8080 -> web-app:5000 -> db:3306
Client -> 127.0.0.1:8080 ----------------> web-app:5000   (direct control)
Client -> 127.0.0.1:8082 -> waf-ml:5001/score            (regex stub)
```

`waf-ml` hiện là scoring API, chưa phải proxy và chưa có model học máy.
Không báo kết quả stub là kết quả ML-WAF. MySQL không publish port ra host;
các HTTP port chỉ bind loopback. Bridge Docker không chặn outbound Internet.

## Cấu hình CRS

- Cùng Dockerfile ghim digest với lab SQLite; không dùng rolling tag cho CRS.
- Engine `On`, request-body inspection `On`, response-body inspection `Off`.
- `CRS_PL` đặt cả blocking và detection PL; fallback `PARANOIA` tương thích cấu hình cũ.
- Inbound anomaly threshold giữ 5, plugins tắt.
- Audit JSON Serial: `logs/waf/integrated/audit.log`.
- Backend structured evidence: `logs/application/integrated/app.jsonl`.
- `/healthz` của backend kiểm tra kết nối DB và trả 503 khi không sẵn sàng.

Version runtime phải lấy từ metadata/audit của từng run. MySQL dùng image
`mysql:8.4`; Python image và dependency pins giữ theo phần tích hợp của nhóm.
Tag Docker có thể thay đổi: runner ghi image identities và backend version,
không suy phiên bản thực tế từ nhãn image.

## Application oracle

Các endpoint và response JSON của nhóm được giữ nguyên. Query ghép chuỗi
có chủ đích vẫn là handler của lab. Trên cùng connection, app chạy thêm query
tham chiếu có bind parameters. Nếu handler trả các user ID ngoài kết quả
tham chiếu, `semantic_effect=true`. Oracle này kiểm chứng mở rộng tập kết quả
và vượt xác thực trên SELECT, không bao phủ mọi loại tác động SQLi.

Request có `X-Lab-Case-ID`; direct control thêm hậu tố `-direct`. App ghi raw
target/body, các cặp tham số, SQL, observed/reference row IDs, SQL error và
semantic effect. Request bị chặn phải có audit evidence và không có app record
cùng ID. HTTP 200 có `db_error` không phải control hợp lệ.

## Tái lập baseline cũ

Lab `docker/waf-crs/compose.yml` dùng project `waf-crs-lab`, port 18080/18081,
Python/SQLite và corpus 13 case. Code runner/corpus/fixture cũ được giữ nguyên.
Nó có log `logs/*/crs/` và output `results/raw/crs/`, độc lập với lab MySQL.

Lab MySQL dùng corpus smoke riêng gồm 3 benign + 3 SQLi; output nằm trong
`results/raw/crs-integrated/`. Không gộp hai corpus/backend vào cùng bảng metric.

## Sửa lỗi P2

Compose có init container ngắn hạn, không mạng, root filesystem read-only; nó
chỉ chown/chmod thư mục audit bind mount và file audit.log cho nginx UID 101.
File được mở bằng touch, không truncate. Healthcheck WAF phải tạo được audit
và thấy file có quyền ghi trước khi đánh dấu healthy. Không dùng chmod 777.

Web-app nhận DB_HOST/DB_PORT/DB_USER/DB_PASSWORD/DB_NAME riêng từ Compose.
DATABASE_URL chỉ là fallback cho cách chạy cũ và cần percent-encode URI.
Runner tích hợp lưu status running/failed/complete, checkpoint partial và chỉ
công bố CSV/JSON cuối khi toàn bộ PL yêu cầu đã hoàn tất.
