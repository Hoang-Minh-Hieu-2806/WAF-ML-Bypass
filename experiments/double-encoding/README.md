# Double encoding — phân biệt byte trên dây và giá trị sau parse

Corpus `dataset/bypass/double-encoding/cases.json` gồm 8 case cho query
`/search` và form `/login`, target Flask/MySQL. `expected_app` được suy ra từ
source và seed; chưa phải kết quả chạy CRS hoặc MySQL thật.

## Giả thuyết cần kiểm tra

Werkzeug parse query/form trước khi handler dùng input. Trong source hiện
tại, handler không gọi URL decoder lần hai. Vì vậy biểu diễn encode hai lần
có thể làm WAF quan sát khác đi nhưng cũng khiến ứng dụng nhận literal percent
text, không tạo hiệu ứng của baseline. Không coi trường hợp inert là bypass.

Ví dụ một ký tự quote đi qua các lớp:

```text
wire query q=%27       -> parser model q="'"
wire query q=%2527     -> parser model q="%27"
```

`raw_query`/`raw_body` là nguồn request duy nhất trong nhóm này. Compiler
không đưa chúng qua `urlencode` lần nữa. Với form, header luôn là
`application/x-www-form-urlencoded`; một thay đổi Content-Type sẽ tạo một
phép thử khác về parser.

| Case | Vai trò | Giá trị app dự kiến chọn | Semantic effect dự kiến |
|---|---|---|---|
| `de-001` | Benign query control | `q=alice` từ `%61lice` | false |
| `de-002` | Baseline search | Biểu thức SQLi baseline sau một lần decode | true |
| `de-003` | Mutation của `002`, controls `001/004` | Còn `%27`, `%20`, `%3D` trong q | false |
| `de-004` | Negative query control của `002` | `q=%61lice` từ `%2561lice` | false |
| `de-005` | Benign form control | `alice / alice123` | false; đăng nhập hợp lệ |
| `de-006` | Baseline login | Username baseline sau một lần decode | true |
| `de-007` | Mutation của `006`, controls `005/008` | Username vẫn chứa percent text | false |
| `de-008` | Negative form control của `006` | `%61lice / alice123` | false |

Hai baseline dùng lại biểu thức đơn giản của `waf-crs/integrated-smoke.json`.
Biến độc lập trong từng cặp baseline/mutation là số lớp encoding. Benign và
negative control xác nhận cùng hiện tượng trên ký tự username thông thường,
không chỉ trên chuỗi có ý định SQLi.

## Kiểm tra và bàn giao

```powershell
python experiments/corpus.py validate
python experiments/corpus.py preview --technique double-encoding
python experiments/corpus.py preview --case de-003
python experiments/corpus.py export --technique double-encoding
```

Preview cho thấy target, body base64 và giá trị parser model chọn. Adapter
phải gửi nguyên target/body bytes đã export; thêm một lớp decode hoặc encode
sẽ thay đổi biến độc lập. Runner CRS hiện tại chưa hỗ trợ raw fields này.

Khi lab sẵn sàng, đối chiếu direct control trước: raw query/body trong evidence,
giá trị đưa vào SQL, SQL error, observed/reference IDs và semantic effect.
Sau đó lấy rule matches/decision từ audit theo correlation ID ở từng PL.
Nếu một case được cho qua nhưng vẫn là percent text tại SQL handler, kết quả
đó chỉ chứng minh input inert được cho qua trên fixture này.

Giới hạn: parser model là stdlib, chưa phải kiểm thử Werkzeug; môi trường có
proxy/app tự decode thêm có thể khác source hiện tại. Dấu `%` trong `/search`
cũng là wildcard LIKE, nên phải giữ seed và query tham chiếu khi xác nhận
hiệu ứng. Không chuyển kết luận sang `/product`, JSON body hoặc SQL dialect
khác khi chưa có control tương ứng.
