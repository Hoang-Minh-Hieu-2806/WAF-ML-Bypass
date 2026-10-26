# HPP — tham số trùng tên và thứ tự giá trị

Corpus: `dataset/bypass/hpp/cases.json`, 8 case theo schema 1.0. Mục tiêu là Flask/MySQL của repo với dữ liệu giả trong `docker/db/init/02-seed.sql`. Đây là kỳ vọng suy ra từ source; chưa gửi request tới MySQL hoặc WAF và chưa có kết luận bypass.

`params` và `form` là danh sách cặp có thứ tự. Không chuyển chúng thành object/dict vì thao tác đó làm mất duplicate keys. Compiler encode mỗi cặp một lần để truyền tới Flask; `raw_query` và `raw_body` đều là `null` trong nhóm này.

| Điểm xử lý | Hành vi cần giữ khi bàn giao |
| --- | --- |
| Query string `/product` | `request.args.get("id", "1")` lấy giá trị đầu tiên của khóa `id`. |
| Form `/login` | Với Content-Type `application/x-www-form-urlencoded`, `request.form.get()` lấy giá trị đầu tiên của từng khóa. |
| Các giá trị còn lại | Có thể xuất hiện trong evidence đa giá trị nhưng không được handler nối hoặc dùng làm biểu thức SQL. |
| Oracle | `semantic_effect=true` cần ID trả về nằm ngoài tập ID của truy vấn bind-parameter tham chiếu. Đăng nhập hợp lệ không tự tạo tác động SQLi. |

| Case | Vai trò / đối chứng | Giá trị app chọn | Kỳ vọng tác động |
| --- | --- | --- | --- |
| `hpp-001` | Baseline product, đối chứng `002/003` | `id=1 OR 1=1` | `true` |
| `hpp-002` | Benign: `id=1&id=2` | `id=1` | `false` |
| `hpp-003` | Âm: `id=1&id=OR 1=1`, baseline `001` | `id=1` | `false` |
| `hpp-004` | Mutation: biểu thức trước, ID benign sau; đối chứng `002/003` | `id=1 OR 1=1` | `true` |
| `hpp-005` | Mutation: đảo thứ tự của `004`; đối chứng `002/003` | `id=1` | `false` |
| `hpp-006` | Baseline login, đối chứng `007/008` | `username=alice`, password chứa OR | `true` |
| `hpp-007` | Benign: password đúng trước password sai | `alice / alice123` | `false` |
| `hpp-008` | Âm: password sai trước password chứa OR, baseline `006` | `alice / wrong` | `false` |

`hpp-004/005` giữ nguyên các giá trị và chỉ đảo thứ tự. `hpp-003` là đối chứng quan trọng cho giả thuyết fragmentation: app hiện tại không ghép giá trị thứ nhất và thứ hai, nên không thể suy ra có tác động chỉ vì các mảnh nhìn chung tạo thành biểu thức SQL. `hpp-007/008` bổ sung cùng quy tắc cho form, với một baseline login riêng để không so nhầm hai endpoint.

`label` biểu thị ý định của case. Vì thế `hpp-005` và `hpp-008` vẫn có nhãn `malicious` khi giá trị app chọn không gây tác động. Không dùng nhãn này thay cho bằng chứng thực thi hoặc dự đoán WAF.

Chạy kiểm tra và xem request biên dịch từ thư mục gốc repo:

```powershell
python experiments/corpus.py validate
python experiments/corpus.py preview --technique hpp
```

Hai lệnh trên chỉ kiểm tra/xem corpus; không phát traffic. Khi bàn giao cho runner, giữ byte request đã biên dịch và correlation ID, rồi lưu riêng SQLi detection, blocking, reached-app, `sql_error`, observed/reference ID và `semantic_effect`. Request được WAF cho qua nhưng app chọn ID benign không đủ chứng minh bypass.

Giới hạn: expectation giả định seed còn nguyên và DB hoạt động. HTTP 200 là hành vi API khi có cả lỗi DB; không phải bằng chứng thành công. Evidence `parsed_pairs/form_pairs` do Werkzeug nhóm theo key, nên với nhiều khóa xen kẽ cần dùng raw target/body để kiểm tra thứ tự trên dây. Bộ case này không giả định WAF dùng first-value, last-value hoặc nối các giá trị; hành vi WAF cần đo riêng.
