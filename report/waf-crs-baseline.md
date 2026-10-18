# Kết quả baseline ModSecurity + CRS — Châu Gia Huy

**Trạng thái:** đã thực thi ngày 10/10/2026 trên lab local.
Run chính thức: `20261010T082249Z-747fde82`, bắt đầu lúc 15:22:49 giờ Việt Nam.
Source được triển khai trên branch `feature/crs`, từ upstream commit `3692e33`.
Phạm vi: phần signature WAF của kế hoạch nhóm; chưa đánh giá ML hay mutation.

## Câu hỏi và thiết kế

PL1, PL2 và PL3 phát hiện/chặn SQLi baseline như thế nào, và có làm tăng
false positive trên input hợp lệ không?

**Giả thuyết trước thực thi:** SQLi cơ bản bị chặn; tăng PL có thể tăng false
positive. Đây là giả thuyết, không dùng làm nhãn kết quả.

Biến độc lập là PL; blocking PL và detection PL cùng thay đổi 1 → 2 → 3.
Corpus, image digest, fixture backend, ngưỡng inbound 5, parser, HTTP method,
headers và encoding được giữ cố định. Response-body inspection tắt để phép
đo tập trung inbound. Không dùng rule exclusion; plugins tắt.

Corpus gồm 8 benign và 5 malicious SQLi, chạy qua WAF ở mỗi PL: **39 request
được đánh giá**. Có thêm 39 direct-control requests, tách correlation ID, để
kiểm chứng ngữ nghĩa của fixture. Healthchecks không thuộc mẫu số.

## Môi trường quan sát

| Thành phần | Version thực tế |
|---|---|
| Host | Windows 11, build 26300 |
| Docker Desktop / Engine | 4.77.0 / 29.5.3, Linux amd64 containers |
| Docker Compose | 5.1.4 |
| Nginx | 1.30.5 |
| ModSecurity / Nginx connector | 3.0.17 / 1.0.4 |
| OWASP CRS | 4.30.0 |
| Backend | Python 3.12.15, SQLite 3.46.1, stdlib HTTP server |
| Runner | Python 3.14.4, standard library |
| ML model / seed | Không áp dụng; corpus cố định, không sampling |

Image WAF:
`owasp/modsecurity-crs@sha256:133267aa811e1a57a23b52ef04b3c30e802bcbe5454588f6d6af1f69f4b2b667`.

Image Python:
`python@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1`.

Corpus SHA-256:
`0ab6e4dc1d48d88c3aff1ebcab4f745e9afeef155984f6b5833edf54928e6e9f`.

Source hashes, Docker version đầy đủ, effective configs và container inspection
nằm trong raw evidence của run. Mạng Compose riêng, các port host chỉ bind
loopback: WAF 18081, direct control 18080. Không có thử nghiệm tới target bên ngoài.

## Định nghĩa trước đo

- **SQLi detection:** audit log có rule `942xxx` cho correlation ID của request.
- **Inbound block:** HTTP 403, rule `949110`, không có backend record của request qua WAF.
- **Reached app:** có backend log cùng correlation ID, không dùng record `-direct`.
- **Semantic effect:** truy vấn trả cả ba sản phẩm hoặc vượt xác thực của fixture.
- **True bypass:** malicious được cho qua, không có SQLi detection và backend
  xác nhận semantic effect. Mẫu số là toàn bộ 5 malicious tại từng PL.
- **Blocking FPR:** benign bị chặn / 8 benign. **Detection FNR:** malicious
  không có SQLi rule / 5 malicious. Errors/thiếu evidence không tính là allowed.

## Kết quả đã quan sát

| PL | SQLi detected | SQLi blocked | SQLi tới app | SQLi có hiệu ứng qua WAF | True bypass | Benign blocked | FPR |
|---|---:|---:|---:|---:|---:|---:|---:|
| 1 | 5/5 (100%) | 5/5 (100%) | 0/5 | 0/5 | 0/5 (0%) | 0/8 | 0% |
| 2 | 5/5 (100%) | 5/5 (100%) | 0/5 | 0/5 | 0/5 (0%) | 1/8 | 12.5% |
| 3 | 5/5 (100%) | 5/5 (100%) | 0/5 | 0/5 | 0/5 (0%) | 3/8 | 37.5% |

Detection FNR là **0/5 = 0%** ở cả ba PL. Tất cả direct controls malicious
đã tạo đúng hiệu ứng; benign controls không gây SQL error hoặc malicious effect.
Rule `942100` (libinjection) xuất hiện trên cả năm SQLi ở PL1, và `949110`
thực thi chặn. SQLI-003 còn kích hoạt các rule SQLi khác; giữ toàn bộ messages
trong `results.json` và audit snapshots để phân tích, không suy rule chỉ từ status.

### False positives và nguyên nhân từ evidence

| Case | PL bị chặn | Input hợp lệ | Rule phát hiện | Nội dung match quan sát |
|---|---|---|---|---|
| BEN-007 | 2, 3 | notes=`price < 100 & stock > 0` | 942131 | `price < 100` trong `ARGS:notes` bị nhận là biểu thức SQL boolean |
| BEN-002 | 3 | `/product?id=2` | 932350 | tên tham số `id` trong `ARGS_NAMES:id` match lệnh Unix `id` |
| BEN-004 | 3 | q=`màn hình` | 920272 | byte UTF-8 ngoài nhóm ký tự ASCII được rule PL3 cho phép |

Các case trên đều có `949110`, HTTP 403 và không có app record qua WAF.
BEN-002 bị chặn do **tên tham số**, không phải do giá trị số 2. BEN-004 là
false positive đối với fixture có chấp nhận tìm kiếm tiếng Việt. Điều này
minh họa rằng nhãn benign phải gắn với hành vi và contract ứng dụng.

## Pipeline đại diện: SQLI-002 ở PL1

Client gửi `/product?id=1+OR+1%3D1`, `Host: localhost:18081`.
Audit ghi `ARGS:id` sau parse là `1 OR 1=1`; `942100` nhận diện SQLi.
Rule `949110` chặn với HTTP 403; backend không có correlation ID tương ứng.

Trong **direct control**, backend parse URL một lần bằng `parse_qsl`, lấy
giá trị đầu tiên nếu key lặp và tạo truy vấn:

```sql
SELECT id,name FROM products WHERE id = 1 OR 1=1
```

SQLite trả ba sản phẩm thay vì sản phẩm id=1, nên oracle xác nhận SQLi này
có ngữ nghĩa độc hại thật trong fixture. Direct control chỉ xác nhận tính
hợp lệ của testcase; không được báo là bypass vì request qua WAF bị chặn.

## Tái lập và evidence

```powershell
python -m unittest discover -s waf-crs -p test_baseline.py -v
python waf-crs/run_baseline.py
```

Đã chạy thành công cả 5 regression checks cho corpus semantics, duplicate
parameter policy, decode-once policy, phân biệt detection/block/bypass và
case-insensitive audit correlation. Compose config validation đã pass.
Lab khởi động healthy; runner hoàn tất cả ba PL với đủ correlated audit entries.

Raw evidence local nằm tại:
`results/raw/crs/20261010T082249Z-747fde82/`.

- `metadata.json`: fingerprint và runtime producer.
- `plN-effective-config.txt`, `plN-compose.json`, `plN-containers.json`:
  cấu hình thực tế và container metadata từng PL.
- `plN-backend-version.txt`, `plN-container.log`: backend version và startup log.
- `plN-audit.json`, `plN-app.json`: snapshots có correlation ID.
- `results.json`, `results.csv`, `summary.json`: kết quả và tổng hợp.

Raw outputs và logs được giữ local theo `.gitignore`; báo cáo này là bản tóm
tắt có thể commit. Khi bàn giao evidence, đóng gói thư mục run riêng, không
force-add tất cả logs hoặc môi trường local.

Hai lượt trước đó là debug/preliminary, không trộn vào bảng trên:
`20261010T081728Z-94cbcb3d` chưa hoàn tất;
`20261010T081908Z-516b1618` dùng Host IP và kích hoạt rule 920350 thêm điểm.
Lượt chính thức loại bỏ nhiễu này bằng Host localhost, không đổi corpus.

## Diễn giải và hardening sơ bộ

Trên corpus này, PL1 đã chặn toàn bộ SQLi; PL2/PL3 chưa tăng detection nhưng
tăng FPR. Có thể giữ PL1 làm baseline hiện tại, mở rộng benign traffic và
mutation corpus trước khi lựa chọn PL triển khai. Không suy kết quả này thành
khuyến nghị PL1 cho mọi ứng dụng hoặc kết luận PL cao không có ích.

Nếu nhóm cần PL3, review rule matches theo contract ứng dụng (tên `id`, UTF-8,
metadata biểu thức). Tạo exception hẹp theo endpoint/parameter nếu bằng chứng
và threat model cho phép, rồi chạy lại malicious regression cùng benign corpus.
Chưa thêm exception trong phép đo này.

## Giới hạn và phần việc còn phụ thuộc nhóm

13 cases không phải benchmark đại diện; fixture dùng parser stdlib và SQLite,
chưa phải web-app Flask/Express cuối cùng. Phải chạy lại khi backend/parser,
image, threshold hoặc contract thay đổi. Chưa thử HPP, double encoding,
case/comment hay parsing discrepancy và chưa có ML model để đối chiếu.
Latency lưu trong CSV là đơn lẻ, không đủ đánh giá throughput hoặc overhead.

Phần signature baseline và PL comparison của Châu Gia Huy đã có implementation
và evidence. Phần hardening cuối kỳ, tích hợp web-app thật và so sánh ML cần
corpus/model của các thành viên khác. Hướng dẫn bàn giao/cleanup và cơ chế
chi tiết: [docs/waf-crs.md](../docs/waf-crs.md).
