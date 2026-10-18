# Module ModSecurity + OWASP CRS — Châu Gia Huy

Phạm vi triển khai theo kế hoạch: ModSecurity v3, CRS, inbound blocking,
audit log, SQLi baseline và so sánh PL1/PL2/PL3. Đây là lab độc lập của module
CRS để bàn giao cho người tích hợp. `crs-test-backend` là fixture kiểm chứng,
không thay thế module `web-app` cuối cùng của nhóm. ML và bốn bộ mutation
thuộc phần việc khác; kết quả baseline không phải kết quả nghiên cứu evasion.

## Chạy lab

Yêu cầu Docker Desktop dùng Linux containers, Docker Compose v2 và Python
3.12+ trên host. Runner chỉ dùng standard library; không cần pip install.
Từ thư mục gốc repo, trong PowerShell:

```powershell
python -m unittest discover -s waf-crs -p test_baseline.py -v
python waf-crs/run_baseline.py
```

Runner build và khởi động lab, chờ healthcheck, chạy PL1–PL3 rồi lưu evidence.
Lệnh này giữ container ở PL cuối cùng để có thể xem/demo tiếp. Dữ liệu SQLite
được tạo lại cho từng request; không cần reset dữ liệu giữa các PL.

Để chỉ chạy một PL:

```powershell
python waf-crs/run_baseline.py --levels 1
```

Để khởi động thủ công:

```powershell
$env:CRS_PL = '1'
docker compose -f docker/waf-crs/compose.yml up -d --build --wait
curl.exe -i 'http://localhost:18081/search?q=laptop'
curl.exe -i 'http://localhost:18081/product?id=1%20OR%201%3D1'
docker compose -f docker/waf-crs/compose.yml ps
```

**Kết quả mong đợi**: request benign trả 200; request SQLi trả 403 với rule
SQLi `942xxx` và blocking `949110` trong audit log. Quan sát thực tế nằm
trong từng thư mục run; không suy ra rule ID chỉ từ HTTP 403.

Port mặc định là `127.0.0.1:18081` (WAF) và `127.0.0.1:18080` (direct control).
Có thể đổi bằng `CRS_PORT` và `CRS_BACKEND_PORT` trong môi trường PowerShell
trước khi chạy. Runner tự đọc cùng hai biến này. Dùng bridge riêng của Compose;
chỉ công bố port trên loopback. Bridge này không chặn outbound Internet;
runner bỏ proxy hệ thống và không follow redirect, mọi request đi tới loopback.
Trên máy hiện tại, bridge `internal: true` không tạo host port mapping hữu dụng,
nên không sử dụng cho client chạy trên host.

Audit log: `logs/waf/crs/audit.log` (JSON từng dòng, Serial).
Backend log: `logs/application/crs/app.jsonl`.
Thư mục output: `results/raw/crs/<UTC-run-id>/`.
Logs/output bị `.gitignore` loại trừ; không force-add toàn bộ raw evidence.

## Cấu hình và version

Hai Dockerfile ghim digest được resolve từ official images ngày 10/10/2026.
Không tự cập nhật rolling tag giữa các thí nghiệm. Khi nâng version, đổi digest
trên branch riêng và chạy lại baseline; không gộp dữ liệu khác version.
Runtime producer trong audit log xác nhận phiên bản thực tế của CRS,
ModSecurity và connector; `plN-effective-config.txt` ghi Nginx version và
cấu hình engine/CRS đã được entrypoint render.

Các biến cố định:

| Cấu hình | Giá trị | Ý nghĩa |
|---|---|---|
| `MODSEC_RULE_ENGINE` | `On` | Thực thi blocking |
| `MODSEC_REQ_BODY_ACCESS` | `On` | Kiểm tra form POST |
| `MODSEC_AUDIT_ENGINE` | `On` | Có evidence cả allowed và blocked |
| `BLOCKING_PARANOIA` | 1, 2, 3 | Biến độc lập của phép so sánh |
| `DETECTION_PARANOIA` | bằng blocking PL | Không chạy thêm rule PL cao ngoài phép so sánh |
| `ANOMALY_INBOUND` | 5 | Ngưỡng chặn giữ nguyên giữa các PL |
| `MODSEC_RESP_BODY_ACCESS` | `Off` | Tách phép đo inbound khỏi outbound filtering |
| `CRS_DISABLE_PLUGINS` | 1 | Baseline chỉ dùng core rules |

Paranoia Level quyết định tập rule được thực thi. Anomaly threshold quyết định
điểm tích lũy cần đạt để chặn; đây là hai tham số khác nhau. Rule SQLi có thể
match mà request chưa đạt ngưỡng chặn. Tăng PL có thể kích hoạt thêm rule trên
input hợp lệ, vì vậy phải báo detection cùng false positive và mẫu số.
Không tăng threshold hoặc thêm exclusions để làm đẹp bảng kết quả.

## Corpus và application oracle

`waf-crs/baseline.json` là corpus nhỏ do nhóm có thể đọc/review: 8 benign và
5 malicious SQLi. Không phải dataset huấn luyện hoặc benchmark đại diện.
`params`/`form` là danh sách cặp theo thứ tự để bảo toàn key lặp khi mở rộng
HPP; JSON object không biểu diễn được duplicate keys một cách đáng tin cậy.

Fixture có GET `/search`, GET `/product`, POST `/login`, GET `/healthz`.
SQLite chỉ chứa ba sản phẩm và một tài khoản giả phục vụ lab. SQL được ghép
chuỗi có chủ đích để kiểm chứng SQLi. Không đưa fixture này vào ứng dụng thật.
Trên mỗi request, log ghi raw target/body, cặp tham số đã parse, câu SQL,
kết quả và `semantic_effect`:

- `/search`, `/product`: SQLi phải trả đủ ba sản phẩm, gồm các hàng ngoài
  điều kiện gốc. Chỉ lỗi SQL hoặc echo payload không phải hiệu ứng này.
- `/login`: truy vấn trả tài khoản dù cặp input không phải thông tin hợp lệ
  đã seed; đây là oracle authentication bypass của fixture.
- Benign: semantic effect phải false và không có SQL error. Các chuỗi trong
  `notes` là metadata hợp lệ được log, không tham gia ghép query.

Mỗi case chạy direct control trước khi gửi qua WAF. Runner dừng nếu control
không tạo đúng hiệu ứng (malicious) hoặc gây lỗi/hiệu ứng (benign). Mỗi request
có `X-Lab-Case-ID` gồm run, PL, case; direct control có hậu tố `-direct` nên
không bị nhầm với request qua WAF.

## Định nghĩa metric trước thực nghiệm

Với N request malicious và B request benign, riêng từng PL:

| Chỉ số | Tử số / mẫu số |
|---|---|
| SQLi detection rate | malicious có rule `942xxx` / N |
| Inbound block rate | malicious HTTP 403 + `949110` + không có app record / N |
| Detection FNR | malicious không có rule `942xxx` / N |
| Blocking FPR | benign bị inbound blocking / B |
| True bypass rate | malicious allowed + không có rule SQLi + app chứng minh hiệu ứng / N |

Runner ghi riêng `reached_app` và `semantic_effect`. Case được cho qua nhưng
không tạo hiệu ứng không phải true bypass. Case đạt hiệu ứng nhưng đã bị phát
hiện dưới threshold cũng không được tính là bypass theo tiêu chí detection
nghiêm ngặt của module; dữ liệu thô vẫn giữ để người đánh giá tính tiêu chí
blocking khác nếu công bố rõ. HTTP/network errors và thiếu audit evidence
làm run incomplete, không được nhập vào confusion matrix như allowed.

## Transformation pipeline

Ví dụ SQLI-002:

```text
Client: /product?id=1+OR+1%3D1
  -> Nginx HTTP parser: request target, Host localhost, header correlation
  -> ModSecurity argument parser: ARGS:id = "1 OR 1=1"
  -> CRS SQLi rule transformations/operator -> anomaly score -> 949110
  -> nếu blocked: backend không nhận request tương ứng
  -> direct control: urllib.parse.parse_qsl decode một lần, first-value-wins
  -> SQLite: SELECT id,name FROM products WHERE id = 1 OR 1=1
  -> trả đủ ba sản phẩm, semantic_effect=true
```

Đây là pipeline baseline; không khẳng định có parsing discrepancy hay double
decoding trong WAF. Các transformation thực tế phụ thuộc từng rule; đọc rule
file trong image ghim digest và `details.match/reference/data` của audit entry.
Backend không decode lần hai và chọn giá trị đầu tiên khi key lặp. Khi nhóm
tích hợp Flask/Express, phải đo lại chính sách parser; không suy từ fixture này.

## Evidence và giới hạn

Mỗi run lưu corpus/source SHA-256, version host/Python/Docker/Compose,
cấu hình render, container inspection, backend Python/SQLite version,
audit/app snapshots, response/raw URL/body, rule messages, CSV và summary.
Không dùng seed ngẫu nhiên cho corpus cố định; UUID chỉ dùng correlation.

Corpus nhỏ nên 100% detection chỉ chứng minh các case đó trên cấu hình đó.
Latency là round-trip đơn lẻ từ host, không phải throughput benchmark.
Chưa có ML model nên không đưa ra so sánh CRS vs ML. Chưa chạy mutation nên
không kết luận hiệu quả đối với HPP, DE, case/comment hoặc parsing discrepancy.

## Bàn giao và cleanup

Người tích hợp có thể dùng build `docker/waf-crs/Dockerfile`, các biến cấu hình
ở Compose và đổi `BACKEND` thành URL service `web-app` thật. Giữ upstream
rules trong image; không mount thư mục rules rỗng đè lên CRS. Khi đổi backend,
phải cập nhật oracle và log schema rồi chạy baseline lại.

Cleanup chỉ xóa container/network của project này, giữ source và log bind mounts:

```powershell
docker compose -f docker/waf-crs/compose.yml down
```

Rollback lab: chạy lại `up -d --build --wait` với `CRS_PL=1`.
Triển khai trên `feature/crs`; cần thành viên khác review trước khi tích hợp.

## Nguồn chính thức đã kiểm tra ngày 10/10/2026

- [Official CRS Docker images, environment variables và proxy configuration](https://github.com/coreruleset/modsecurity-crs-docker)
- [CRS Paranoia Levels](https://coreruleset.org/docs/2-how-crs-works/2-2-paranoia_levels/)
