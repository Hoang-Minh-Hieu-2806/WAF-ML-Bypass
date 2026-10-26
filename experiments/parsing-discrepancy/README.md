# Parsing discrepancy — giả thuyết parser và đối chứng

Corpus `dataset/bypass/parsing-discrepancy/cases.json` có 12 case, target
Flask/MySQL `/login`. Các kỳ vọng mô tả input mà handler dự kiến sử dụng;
không giả định WAF parse giống hoặc khác ứng dụng khi chưa có audit thực đo.

Source handler chọn `request.get_json(silent=True) or request.form or {}`.
Nó không đọc query string để lấy credential và không URL-decode các giá trị
string đã parse từ JSON. Quy tắc này khác fixture SQLite, nơi query pairs
được ghép trước form rồi áp dụng first-value-wins. Không dùng oracle/parser
của SQLite làm ground truth cho các case dưới đây.

| Nhóm | App theo source / parser model | Điều cần quan sát tại WAF |
|---|---|---|
| JSON key trùng | Python JSON object giữ giá trị cuối; raw body giữ cả hai key | WAF nhận diện giá trị nào, ở biến/rule nào |
| Query và form cùng key | `/login` chỉ dùng form khi JSON không được chọn | WAF kiểm query/form riêng hay gộp và rule match ở đâu |
| Content-Type | JSON text dưới `text/plain` không được handler lấy qua JSON/form | Body processor/rule matches theo media type |
| Percent text trong JSON | `%27`/`%61` vẫn là literal, không URL-decode thành quote/a | Transformations có làm cách nhìn của rule khác app không |

`raw_body` là chuỗi bảo toàn JSON có key trùng. Không thay nó bằng object
Python/JSON trước khi gửi; thao tác đó sẽ làm mất thứ tự/key trùng của phép thử.
Các case query/form dùng ordered pairs để giữ representation như khai báo.

| Case | Vai trò / mối liên hệ | Giá trị handler dự kiến dùng | Semantic effect |
|---|---|---|---|
| `pd-001` | Benign JSON control | `alice / alice123` | false; xác thực hợp lệ |
| `pd-002` | Baseline JSON | Username baseline / password sai | true |
| `pd-003` | Mutation của `002`, controls `001/004` | JSON username cuối là baseline | true |
| `pd-004` | Negative của `002`, đảo key so với `003` | JSON username cuối là alice, password sai | false |
| `pd-005` | Benign form control | `alice / alice123` | false; xác thực hợp lệ |
| `pd-006` | Baseline form | Username baseline / password sai | true |
| `pd-007` | Mutation của `006`, controls `005/008` | Form alice/password sai, bỏ query baseline | false |
| `pd-008` | Negative của `006` | Form password sai dù query credential đúng | false |
| `pd-009` | Mutation của `002`, controls `001/010` | Rỗng: JSON text gửi dưới text/plain | false |
| `pd-010` | Negative của `002` | Rỗng: form text gửi dưới text/plain | false |
| `pd-011` | Mutation của `002`, controls `001/012` | Username JSON vẫn percent-encoded | false |
| `pd-012` | Negative của `002` | Username JSON literal `%61lice` | false |

Ở `pd-003/004` chỉ đổi thứ tự key. Ở `pd-009` giữ body baseline và thay
Content-Type. `pd-011/012` là đối chứng với nhóm double-encoding: decoder
phải được gắn với loại input, không áp cùng một preprocessing pipeline cho
query/form/JSON.

## Kiểm tra và bàn giao

```powershell
python experiments/corpus.py validate
python experiments/corpus.py preview --technique parsing-discrepancy
python experiments/corpus.py preview --case pd-003
python experiments/corpus.py export --technique parsing-discrepancy
```

Các lệnh chỉ compile/kiểm tra offline. Để đo, gửi direct control và request
qua CRS với correlation ID riêng; ghi content type, raw body/target,
request bytes, query thực tế, reference/observed IDs và audit messages.
Chỉ một khác biệt parser được quan sát ở cả hai phía mới hỗ trợ kết luận
parsing discrepancy; app model hoặc HTTP 200 riêng lẻ chưa đủ.

Giới hạn evidence hiện tại: app JSONL hardcode mô tả parser
`first-value-wins`, còn hai trường query/form pairs không chứa JSON object.
Không dùng chuỗi mô tả này làm chứng cứ JSON chọn key đầu. Cần đọc raw body,
SQL/ID kết quả, đồng thời bổ sung instrumentation ở app trong lượt tích hợp
nếu muốn tự động xác nhận JSON selected fields. Các byte encoding không hợp
lệ không thuộc bộ case v1; app hiện decode raw body bằng UTF-8 replacement.

Toàn bộ semantic-effect/SQL-error expectations đều dựa trên source và seed,
chưa kiểm chứng trên MySQL/CRS thật. Đổi parser/JSON provider/DB state cần đo
lại, không đổi kỳ vọng theo nhãn từ regex ML stub.
