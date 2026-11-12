# Giải thích triển khai ModSecurity + OWASP CRS để báo cáo và bảo vệ

Tài liệu mô tả cách triển khai trong nhánh `feature/crs` của nhóm. Các lệnh
là hướng dẫn tái lập; một dòng lệnh có kết quả kỳ vọng không đồng nghĩa với
kết quả đã đo ở lần chạy hiện tại. Kết quả đã đo nằm trong các thư mục run
và báo cáo tương ứng.

**Câu giới thiệu có thể dùng khi thầy hỏi**

“Em triển khai signature WAF bằng Docker. Image OWASP đã tích hợp Nginx,
ModSecurity v3 và OWASP CRS. Em cấu hình reverse proxy đến backend lab,
bật blocking và audit JSON, rồi kiểm chứng request hợp lệ, SQLi và PL1–PL3
bằng cả WAF log lẫn application evidence.”

**1. Phân biệt ba thành phần**

| Thành phần | Vai trò trong lab |
|---|---|
| Nginx | Nhận HTTP và reverse proxy đến backend khi request được phép |
| ModSecurity v3 | Engine phân tích/kiểm tra transaction và thực thi các rule |
| ModSecurity–Nginx connector | Kết nối các bước xử lý HTTP của Nginx với engine |
| OWASP CRS | Bộ rule phát hiện generic attack/protocol anomaly chạy trên engine |

ModSecurity và CRS là hai thành phần khác nhau. Lab không chỉ dùng regex
SQLi tự viết; nó dùng core rules đi kèm image. Ví dụ `942100` là SQLi rule
đã xuất hiện trong audit của baseline; một rule match chưa đủ kết luận bị chặn.

Nguồn thành phần/image: [official CRS Docker repository](https://github.com/coreruleset/modsecurity-crs-docker).

**2. Kiểm tra môi trường**

Máy đã có Docker Desktop và Python; phần việc thực hiện là kiểm tra và dùng
chúng để dựng Linux containers, không phải tự compile ModSecurity trên Windows.

```powershell
Set-Location 'D:\UIT\KY5\Project\04-WAF-Adversarial\WAF-ML-Bypass'
docker version
docker compose version
python --version
```

`docker version` cần thấy cả client và server. Nếu chỉ thấy client hoặc lỗi
named pipe, Docker Engine chưa truy cập được. Docker Desktop phải hoạt động
với Linux containers để chạy các image của lab.

**3. Lấy image đã tích hợp sẵn và ghim phiên bản**

File `docker/waf-crs/Dockerfile` chỉ có base image:

```dockerfile
FROM owasp/modsecurity-crs@sha256:133267aa811e1a57a23b52ef04b3c30e802bcbe5454588f6d6af1f69f4b2b667
```

Khi chạy Compose build, Docker sẽ lấy image base nếu chưa có và tạo image
của service. Trong dự án này không có bước `apt install modsecurity` hay
clone source rồi tự compile thư viện/connector. Image upstream đã làm phần đó.

Digest ghim nội dung image; rolling tag có thể đổi theo thời gian. Ghim CRS
giúp so sánh các PL mà không vô tình thay engine/rules giữa hai lần đo.
Digest không thay cho việc đọc runtime version: phải xem audit producer.

Đã ghi nhận trong run 18/10: Nginx 1.30.5, ModSecurity 3.0.17,
connector 1.0.4, CRS 4.30.0. Đây là version của image/run đó, không gọi là
“bản mới nhất” nếu chưa kiểm tra.

**4. Dựng backend đối chứng trước**

Có hai topology, phải nói đúng topology đang demo:

| Lab | Qua WAF | Direct control | Backend |
|---|---|---|---|
| CRS độc lập | 127.0.0.1:18081 | 127.0.0.1:18080 | Python stdlib + SQLite |
| Tích hợp | 127.0.0.1:8081 | 127.0.0.1:8080 | Flask/PyMySQL + MySQL |

Backend có chủ đích ghép chuỗi SQL trên dữ liệu giả để xác nhận ảnh hưởng
SQLi. Nếu chỉ echo payload hoặc trả lỗi SQL, chưa có bằng chứng thực thi
đúng ngữ nghĩa độc hại. Không dùng fixture này như ứng dụng an toàn thực tế.

Luồng tích hợp:

```text
Client -> localhost:8081 -> Nginx/ModSecurity/CRS -> web-app:5000 -> db:3306
Client -> localhost:8080 ----------------------> web-app:5000  (đối chứng)
```

`BACKEND=http://web-app:5000` là tên service trong Docker network. Không đặt
`localhost:8080` làm upstream: localhost trong container WAF là chính container
WAF. Host port 8081 ánh xạ vào port 8080 của container WAF; đó là hai không gian
port khác nhau. MySQL không publish port ra host; HTTP chỉ bind loopback.

**5. Cấu hình WAF trong Compose**

| Biến trong Compose | Giá trị | Mục đích |
|---|---|---|
| MODSEC_RULE_ENGINE | On | Cho phép thực thi blocking |
| MODSEC_REQ_BODY_ACCESS | On | Cho phép kiểm tra request body, cần cho form POST |
| MODSEC_RESP_BODY_ACCESS | Off | Tách thực nghiệm inbound khỏi response inspection |
| MODSEC_AUDIT_ENGINE | On | Ghi audit cho cả allowed và blocked trong lab |
| MODSEC_AUDIT_LOG_TYPE | Serial | Ghi các transaction vào một file |
| MODSEC_AUDIT_LOG_FORMAT | JSON | Để runner đọc và liên kết evidence |
| BLOCKING_PARANOIA | CRS_PL | PL dùng cho quyết định blocking |
| DETECTION_PARANOIA | CRS_PL | PL thực thi detection trong phép so sánh này |
| ANOMALY_INBOUND | 5 | Threshold inbound giữ cố định giữa các PL |
| CRS_DISABLE_PLUGINS | 1 | Baseline tập trung vào core rules |

Đây là biến môi trường mà entrypoint image dùng để render cấu hình.
Ví dụ `MODSEC_RULE_ENGINE=On` dẫn tới `SecRuleEngine On`; PL được đưa vào
các biến transaction trong CRS setup. Phải đọc file đã render để biết giá trị
hiệu lực, không chỉ nhìn YAML hoặc `.env`.

Bản sửa P2 có thêm init container chạy một lần để đặt quyền audit cho UID 101
của nginx. Init không có mạng, không truncate log. WAF healthcheck còn kiểm tra
file audit có dữ liệu và quyền ghi. `Exited (0)` của init là trạng thái bình thường.

**6. Khởi động lab và kiểm tra cấu hình hiệu lực**

Để học/demo module CRS riêng trước, không cần cấu hình MySQL:

```powershell
$env:CRS_PL = '1'
docker compose -f docker/waf-crs/compose.yml config --quiet
docker compose -f docker/waf-crs/compose.yml up -d --build --wait
docker compose -f docker/waf-crs/compose.yml ps -a
```

Lab tích hợp dùng `.env` hiện có hoặc copy từ `.env.example` lần đầu. Đặt mật
khẩu lab riêng trước khi DB được khởi tạo. Compose truyền DB_PASSWORD nguyên
văn; không ghép mật khẩu chưa encode vào URL. Không in/commit `.env`.

```powershell
if (-not (Test-Path -LiteralPath .env)) { Copy-Item .env.example .env }
$env:CRS_PL = '1'
$env:MODSEC_RULE_ENGINE = 'On'
docker compose config --quiet
docker compose up -d --build --wait --wait-timeout 240
docker compose ps -a
```

Kiểm tra file thực tế bên trong WAF tích hợp:

```powershell
docker compose exec -T waf-crs nginx -t
docker compose exec -T waf-crs cat /etc/modsecurity.d/modsecurity.conf
docker compose exec -T waf-crs cat /etc/modsecurity.d/owasp-crs/crs-setup.conf
```

Tìm `SecRuleEngine On`, request-body access, audit JSON, blocking/detection PL
và inbound threshold 5. `nginx -t` kiểm tra cấu hình, không tự chứng minh audit
log ghi được hoặc SQLi đã bị chặn; cần bước kiểm chứng request tiếp theo.

**7. Gửi benign request trước, rồi SQLi**

Ví dụ dưới đây dùng lab SQLite ở 18080/18081. Với lab tích hợp, đổi port và
nhớ dữ liệu/table/response của MySQL khác SQLite.

```powershell
$benignId = 'demo-benign-' + [guid]::NewGuid().ToString('N')
curl.exe -i -H "X-Lab-Case-ID: $benignId" 'http://localhost:18081/search?q=laptop'

$sqliId = 'demo-sqli-' + [guid]::NewGuid().ToString('N')
curl.exe -i -H "X-Lab-Case-ID: $sqliId" 'http://localhost:18081/product?id=1%20OR%201%3D1'

curl.exe -i -H "X-Lab-Case-ID: $sqliId-direct" 'http://localhost:18080/product?id=1%20OR%201%3D1'
```

Kỳ vọng: benign qua WAF trả 200; SQLi qua WAF bị chặn; direct control chứng minh
backend dễ bị SQLi. Dùng URL encoding vì dấu cách không gửi nguyên dạng trong
request target. `curl.exe` giúp gọi đúng curl trong PowerShell.

Pipeline của ví dụ:

```text
Client bytes: id=1%20OR%201%3D1
 -> HTTP/argument parsing
 -> WAF kiểm tra ARGS:id, chạy rule/transformations tương ứng
 -> cộng anomaly score, kiểm tra threshold
 -> blocked: không forward đến backend
 -> direct control: parser backend nhận "1 OR 1=1"
 -> SQLite xây SELECT id,name FROM products WHERE id = 1 OR 1=1
 -> trả ba sản phẩm thay vì một
```

Đây là ví dụ baseline. Không suy ra WAF luôn decode hai lần hoặc mọi SQLi dùng
cùng transformation. Phải đọc rule và matched data của từng case để kết luận.

**8. Đọc bằng chứng và phân biệt detection/blocking/bypass**

Lab riêng: `logs/waf/crs/audit.log` và `logs/application/crs/app.jsonl`.
Lab tích hợp: `logs/waf/integrated/audit.log` và
`logs/application/integrated/app.jsonl`.

```powershell
Get-Content -LiteralPath logs/waf/crs/audit.log -Tail 5
Get-Content -LiteralPath logs/application/crs/app.jsonl -Tail 10
```

| Điều cần chứng minh | Bằng chứng |
|---|---|
| SQLi được phát hiện | Audit cùng correlation ID có SQLi rule 942xxx |
| Inbound bị chặn | HTTP 403 + 949110 + không có app record cùng ID |
| Đến backend | Có app record cùng ID, không dùng bản có hậu tố -direct |
| Có hiệu ứng | Oracle backend chứng minh kết quả/query bị thao túng |
| True bypass theo module | Malicious allowed + không có SQLi detection + có hiệu ứng |

403 đứng riêng có thể do ứng dụng/proxy/lỗi khác, nên không đủ chứng minh CRS
đã chặn SQLi. Direct control có hiệu ứng chỉ xác nhận testcase hợp lệ, không
phải bypass. Trường hợp detected nhưng chưa đủ điểm chặn được lưu riêng,
không được gộp với “không phát hiện”.

Trong anomaly scoring, rule detection cộng điểm; bước blocking đánh giá tổng
điểm so với threshold. Không phải mỗi rule match đều chặn ngay.
Nguồn: [CRS anomaly scoring](https://coreruleset.org/docs/2-how-crs-works/2-1-anomaly_scoring/).

**9. So sánh PL1–PL3 bằng cùng corpus**

```powershell
python -m unittest discover -s waf-crs -p 'test_*.py' -v
python waf-crs/run_baseline.py
# Lab tích hợp đã build:
python waf-crs/run_integrated_smoke.py --levels 1 2 3
```

PL là tập rule kiểm tra; threshold là ngưỡng điểm chặn. Tăng PL bổ sung rule
và có thể tăng false positive. Phép đo giữ threshold 5, corpus, image và backend
cố định trong từng phép so sánh; đặt detection/blocking PL bằng nhau để không
thêm biến gây nhiễu. Nguồn: [CRS FAQ về PL](https://coreruleset.org/faq/).

Lab riêng dùng 8 benign + 5 SQLi; smoke MySQL dùng 3 benign + 3 SQLi. Không trộn
hai corpus/backend vào một tỷ lệ. Kết quả 100% trên corpus nhỏ không chứng minh
WAF chặn mọi SQLi hoặc PL1 tối ưu cho mọi ứng dụng.

Runner lưu cấu hình hiệu lực, version, hashes, audit/app snapshots và CSV/JSON.
Bản sửa P2 của runner MySQL thêm `status=running/failed/complete`; chỉ dùng kết
quả cuối khi complete và đủ completed_levels. File partial là checkpoint.

**10. Những câu thầy/nhóm thường hỏi**

- **Em tự cài/compile ModSecurity à?** Em dùng image OWASP tích hợp sẵn, ghim
  digest và cấu hình triển khai; không tự compile engine/connector ở repo này.
- **Công việc của em ngoài chạy image là gì?** Wiring reverse proxy, blocking,
  audit, PL, corpus, direct controls, correlation, oracle, runner và phân tích FP.
- **DetectionOnly khác On thế nào?** DetectionOnly dùng để quan sát rule matches
  mà không thực thi disruptive blocking; demo blocking của em dùng On.
- **PL3 có luôn tốt hơn PL1?** PL3 có thêm rule nhưng phải đo cả FP theo contract
  ứng dụng. Kết quả lab chỉ cho biết trên corpus và cấu hình đang xét.
- **Tại sao tắt response inspection?** Để tập trung đo inbound blocking, tránh
  nhầm request bị chặn trước backend với response bị chặn sau khi app đã xử lý.
- **Ứng dụng dùng SQL ghép chuỗi có phải lỗi quên sửa?** Đây là fixture cố ý dễ
  bị SQLi trên dữ liệu giả để có oracle; không dùng thiết kế đó cho app an toàn.
- **WAF cho qua đã là bypass chưa?** Chưa; cần chứng minh hiệu ứng ứng dụng và
  nói rõ dùng tiêu chí detection-based hay blocking-based.
- **Tại sao cần direct control?** Nếu payload không khai thác được backend ngay
  cả khi đi thẳng, nó không phải đối chứng hợp lệ để đánh giá WAF.
- **Tại sao có file log mà vẫn kiểm tra?** File có thể cũ/không ghi được. Phải tìm
  transaction mới cùng correlation ID, đồng thời kiểm tra app evidence.
- **Có thể nói “WAF không có bypass” không?** Chỉ nói “không ghi nhận true bypass
  trong các case đã thử ở cấu hình đó”; các mutation/attack khác cần đo riêng.

**Tài liệu và evidence để mở khi bảo vệ**

- `docker/waf-crs/Dockerfile`: image pin.
- `docker/waf-crs/compose.yml`: lab module; `docker-compose.yml`: lab tích hợp.
- `docs/waf-crs.md`: thiết kế/metric; `docs/quickstart-lab.md`: thao tác.
- `report/waf-crs-baseline.md`, `report/crs-docker-integration.md`: kết quả đã đo.
- `results/raw/crs/`, `results/raw/crs-integrated/`: raw evidence local, không commit.

Dừng lab bằng `docker compose down` hoặc thêm `-f docker/waf-crs/compose.yml`
cho lab riêng. Các log bind mount/volume DB vẫn được giữ; không dùng `down -v`
khi cần bảo toàn dữ liệu.
