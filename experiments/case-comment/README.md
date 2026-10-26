# Case/comment — biến thể từ khóa và khoảng trắng SQL

Corpus: `dataset/bypass/case-comment/cases.json`, 8 case theo schema 1.0. Kỳ vọng dựa trên các handler Flask/MySQL và seed hiện có; chưa đo MySQL/WAF, nên các case là giả thuyết cần kiểm chứng và không được báo cáo như bypass đã xác nhận.

| Lớp xử lý | Giả thuyết trong corpus |
| --- | --- |
| HTTP query | Compiler encode chuỗi trong ordered pairs một lần; Werkzeug giải mã thành đúng giá trị `expected_app.selected`. |
| `/search` | Handler chèn `q` vào `username LIKE '%{q}%'`; baseline cân bằng quote và thêm một điều kiện OR đúng. |
| SQL token | `OR/LIKE` dùng chữ hoa thường; `/**/` chỉ thay khoảng trắng giữa các token hoàn chỉnh. Không chẻ `OR` thành `O/**/R`. |
| Literal | Từ khóa và dấu comment nằm bên trong chuỗi LIKE vẫn là dữ liệu khi không thoát quote. |
| Oracle | So sánh ID với truy vấn bind-parameter, không coi HTTP 200, echo payload hoặc nhiều dòng là bằng chứng độc lập. |

| Case | Vai trò / thay đổi | Đối chứng và kết quả app dự kiến |
| --- | --- | --- |
| `cc-001` | Baseline search: `zz' OR '1'='1' OR username LIKE 'zz` | So với `cc-002/003`; tác động `true`. |
| `cc-002` | Benign: `UNION SELECT OR /* note */` nằm trong literal | Không thoát chuỗi LIKE; tác động `false`. |
| `cc-003` | Âm: đổi điều kiện thành `'1'='2'` | Baseline `cc-001`; seed không có username đầu/cuối `zz`, tác động `false`. |
| `cc-004` | Mutation: `oR`, `LiKe` | Baseline `cc-001`, controls `cc-002/003`; tác động `true`. |
| `cc-005` | Mutation: `/**/` thay khoảng trắng | Baseline `cc-001`, controls `cc-002/003`; tác động `true`. |
| `cc-006` | Mutation: kết hợp case và comment | Baseline `cc-001`, controls `cc-002/003`; tác động `true`. |
| `cc-007` | Baseline product: `1 OR 1=1` | Ngữ cảnh số riêng; tác động `true`. |
| `cc-008` | Âm product: `1 OR 1=2` | Baseline `cc-007`; tác động `false`. |

Ví dụ SQL sau khi app chèn baseline search:

```sql
SELECT id, username FROM users
WHERE username LIKE '%zz' OR '1'='1' OR username LIKE 'zz%'
```

Biến thể comment giữ nguyên các token và điều kiện của baseline. `cc-003` giữ cấu trúc quote nhưng thay điều kiện đúng thành sai, đồng thời hai nhánh LIKE không khớp seed. Cặp `cc-007/008` bổ sung mốc ở ngữ cảnh số; không dùng nó thay cho controls của các mutation ở `/search`.

Chạy từ thư mục gốc repo:

```powershell
python experiments/corpus.py validate
python experiments/corpus.py preview --technique case-comment
```

Hai lệnh chỉ kiểm tra/xem request, không gửi traffic. Runner cần bảo toàn request đã biên dịch, đối chiếu baseline và cả hai loại control trong cùng PL/cấu hình, rồi ghi riêng detection, blocking và hành vi app. Nhãn `malicious` ở đối chứng âm mô tả ý định; nó không bắt buộc `semantic_effect=true`.

Giới hạn: corpus chỉ dùng block comment thông thường giữa token, không đại diện cho mọi kiểu comment hoặc mọi SQL dialect. Expectation của product phụ thuộc phép ép kiểu MySQL khi bind chuỗi vào cột số; cần kiểm chứng với phiên bản DB thực tế. Các case search giả định fixture còn nguyên, không có username tiền tố/hậu tố `zz`. Nếu DB lỗi, HTTP vẫn có thể là 200 và oracle chưa chứng minh được hiệu ứng. Chưa có ground truth về WAF detection/blocking cho bất kỳ case nào.
