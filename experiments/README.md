# Thí nghiệm payload và đối chứng

Phần của Long gồm corpus phiên bản hóa, định nghĩa request chính xác,
baseline/đối chứng và phân tích parser cho bốn nhóm. Mỗi thư mục kỹ thuật có
`README.md` và `plan.json`. Automation gửi request và tổng hợp CRS–ML thuộc
runner chung; công cụ ở đây chỉ validate/preview/export, không gửi HTTP.

## Kiểm tra offline

Chạy từ repo root với Python 3.10+; không cần pip install:

```powershell
python experiments/corpus.py validate
python -B -m unittest discover -s experiments -p test_corpus.py -v
python experiments/corpus.py preview --technique hpp
python experiments/corpus.py preview --case de-003
python experiments/corpus.py export --technique parsing-discrepancy
```

`validate` kiểm tra cấu trúc, ID, lineage/control, các plan trỏ đúng corpus và so sánh
`expected_app.selected` với parser model đọc từ logic `web-app/app.py`.
Parser model sử dụng `urllib.parse`/`json` stdlib; không chạy Flask, MySQL
hoặc ModSecurity, không xác nhận `semantic_effect`/`sql_error` tại runtime.
JSON Schema cho công cụ tích hợp ở `dataset/bypass/schema.json`.

`preview` bổ sung query/form pairs và giá trị dự kiến được handler chọn.
`export` xuất JSON với target tương đối, headers và body base64/độ dài bytes.
Base64 là cách bảo toàn request body cho adapter, không phải thêm một lớp
mã hóa HTTP. Cả hai luôn ghi `measurement_status: not-run`.

## Quy trình thực nghiệm để bàn giao automation

1. Validate và đóng băng corpus, source/schema hashes, image identities,
   PL, threshold, parser/framework versions và dữ liệu fixture đang dùng.
2. Mỗi mutation phải chạy cùng baseline, benign control và negative control
   được liên kết. Ghi log riêng cho direct control và request qua WAF.
3. Adapter gửi method, target, headers và bytes đã export. Giữ query order,
   duplicate JSON keys, Content-Type và mức percent encoding. Transport tự
   thêm Host, Content-Length chính xác và X-Lab-Case-ID duy nhất; không follow
   redirects và không đổi đích ra ngoài lab.
4. Kiểm chứng direct control trên **Flask/MySQL** trước khi diễn giải WAF.
   Đối chiếu app JSONL: query, selected inputs/raw body, reference/observed
   IDs, `sql_error`, `semantic_effect`. Nếu khác kỳ vọng, giữ kết quả và đánh
   dấu expectation mismatch; không đổi nhãn dựa trên HTTP 200.
5. Chạy CRS PL1/2/3 với cùng threshold 5. Ghi riêng HTTP status, SQLi rules
   `942xxx`, inbound block `949110`, app reached và semantic effect. Khi
   cần so sánh ML, giữ nguyên input representation/normalization contract;
   API hiện là regex stub, chưa có kết quả ML để báo cáo.
6. Chỉ gọi bypass khi request qua WAF có hiệu ứng được chứng minh. Nếu dùng
   tiêu chí detection-based của CRS, thêm điều kiện không có SQLi detection;
   đồng thời giữ trường hợp detected-but-allowed có hiệu ứng để không mất
   thông tin. Negative control inert không phải một bypass thất bại có cùng
   ngữ nghĩa thực thi với baseline.

Kết quả thực đo phải lưu ngoài corpus cùng run ID, source/corpus hashes,
audit/app/response snapshots và trạng thái run hoàn chỉnh/chưa hoàn chỉnh.
Không ghi đè kỳ vọng source bằng quan sát của một PL.

## Giới hạn cần giữ trong báo cáo

- Corpus nhắm backend Flask/MySQL với seed `docker/db/init/`; SQLite fixture
  có parser, schema và SQL khác, đặc biệt `/login` trộn query trước form.
- Các biến đổi chỉ là giả thuyết để đo. Không có kết luận đã vượt CRS từ
  việc một chuỗi trông khác hoặc bị regex stub gán nhãn benign.
- HPP không tự động có fragmentation: app hiện chọn một value, không nối các
  fragment. Double encoding không tự động được decode hai lần tại backend.
- `expected_app.http_status=200` là contract API lab. Cần kiểm tra cả SQL error
  và oracle; không coi mọi 200 là executed attack.
- Không dùng corpus nhỏ hoặc latency một lần để suy hiệu năng triển khai.

## Trạng thái triển khai

Đã có định nghĩa corpus, validator/compiler offline, regression tests và
protocol theo từng nhóm. Chưa có quan sát CRS/MySQL cho corpus mới. Runner
`waf-crs/run_baseline.py` và `run_integrated_smoke.py` tiếp tục dùng corpus
riêng; cần adapter cho export v1 trước khi chạy phép đo các nhóm này.
