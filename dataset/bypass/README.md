# Corpus payload và đối chứng — Lê Đình Long

Corpus v1.0 dành cho **web-app Flask/PyMySQL/MySQL** hiện tại. Bốn bộ case
nằm ở `hpp/`, `double-encoding/`, `case-comment/`, `parsing-discrepancy/`.
Các case chỉ dùng dữ liệu giả và các SELECT/authentication handler của lab.

Mọi `expected_app` là **kỳ vọng từ source**, chưa phải kết quả đo MySQL/CRS.
Thư mục này không công bố payload nào đã bypass WAF. `semantic_effect=false`
chỉ nói oracle mở rộng tập user ID không dự kiến báo hiệu ứng; không chứng
minh không có mọi dạng SQLi. Quyết định WAF phải được quan sát từ audit.

## Schema và liên kết

`schema.json` là JSON Schema Draft 2020-12; mỗi `cases.json` là một array.
`python experiments/corpus.py validate` kiểm cấu trúc, quy tắc ngữ nghĩa,
liên kết và giá trị handler dự kiến chọn bằng parser model stdlib.
Lệnh này không gọi một JSON Schema engine hoặc framework Flask thật.

| Field | Ý nghĩa |
|---|---|
| `schema_version` | `1.0` |
| `id`, `technique`, `title` | ID duy nhất toàn corpus; nhóm kỹ thuật và mô tả |
| `target` | `flask-mysql`; không chuyển kỳ vọng sang SQLite |
| `label` | Ý định input `benign`/`malicious`; không phải nhãn bypass đo được |
| `role` | `baseline`, `mutation`, `benign-control`, `negative-control` |
| `baseline_id` | Mutation/negative liên kết baseline cùng endpoint và kỹ thuật |
| `control_ids` | Mutation liên kết ít nhất một benign và một negative cùng endpoint |
| `request` | Method, path, ordered params/form, headers và raw query/body |
| `expected_app.selected` | Giá trị handler dự kiến dùng sau parse |
| `expected_app.semantic_effect` | Kỳ vọng oracle ID mới: true/false; null nếu chưa xác định |
| `expected_app.sql_error` | Kỳ vọng lỗi SQL: true/false; null nếu chưa xác định |
| `expected_app.http_status` | API lab hiện trả 200, kể cả khi có `db_error` |
| `note` | Cơ chế và giới hạn; không thay bằng kết quả thực nghiệm |

Baseline là input malicious dự kiến tạo hiệu ứng trên direct app. Benign
control không có ý định tấn công. Negative control cho thấy một biến đổi
không tạo hiệu ứng, ví dụ chỉ đổi thứ tự key hoặc giữ encoding như ký tự
literal. Label malicious nhưng hiệu ứng false là hợp lệ; không đưa các case
này vào mẫu số ASR của payload có ngữ nghĩa thực thi nếu chưa xác nhận direct
control. Liên kết giữ các trường hợp đó riêng với baseline có tác động.

## Biểu diễn request

- `params` và `form` là **danh sách cặp string**, ví dụ
  `[["id", "1"], ["id", "2"]]`. Giữ cả thứ tự và khóa trùng; không ép thành dict.
- Chỉ dùng một nguồn cho mỗi phần: `raw_query != null` thì `params=[]`;
  `raw_body != null` thì `form=[]`. Chuỗi rỗng là một raw field có chủ ý.
- Params/form được `urlencode` UTF-8 đúng một lần. Raw query được ghép nguyên
  dạng vào target; raw body được chuyển UTF-8 thành bytes đúng một lần.
- JSON có key trùng nằm trong **chuỗi `raw_body`**. Không viết key trùng trong
  object của định nghĩa corpus vì JSON loader có thể làm mất case.
- Header Content-Type là một biến thí nghiệm. Các header do transport quản lý
  như Host, Content-Length và X-Lab-Case-ID không nằm trong corpus.
- Chỉ dùng ba route của fixture; không có URL đích trong dữ liệu. Automation
  chọn local endpoint và correlation ID khi thực thi.

## Tương thích với phần còn lại

Mẫu ở `docs/interfaces.md` là giao diện dự kiến dùng `params` object và
`expected_app` string. Corpus này đặt phiên bản riêng để thể hiện những thông
tin mẫu cũ chưa biểu diễn: duplicate keys, raw body và kỳ vọng ứng dụng tách
khỏi WAF. Giữ nguyên tài liệu/interface và runner hiện có khi bàn giao bản
v1.0 này cho review tích hợp.

`request.method/path/params/form` dùng cùng hình dạng với corpus CRS, nhưng
hai runner CRS **chưa đọc corpus này**: đường dẫn corpus đang cố định, raw
fields/headers chưa được hỗ trợ đầy đủ, và chúng yêu cầu mọi malicious
direct control đều có hiệu ứng. Không copy corpus này đè `baseline.json`.

`experiments/corpus.py export` tạo request đã biên dịch cho automation:
`schema_version=1.0`, `representation=compiled-http-request-v1`, relative
`target`, headers, `body_base64`, `body_length`, lineage và kỳ vọng.
Adapter phải dùng target/body đã biên dịch, không decode/re-encode thêm.
Xem quy trình và ranh giới đo lường tại `experiments/README.md`.

Các nhóm mutation có chung baseline là dữ liệu liên quan, không phải các mẫu
độc lập. Corpus nhỏ này dùng regression/research, không phải benchmark ML;
nếu tận dụng cho ML phải giữ cùng family/baseline trong một split để tránh
đưa biến thể của cùng payload vào cả train và test.
