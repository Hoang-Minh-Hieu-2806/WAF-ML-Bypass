# Kiểm chứng sửa ba P2 — 27/10/2026

Phạm vi: branch feature/crs, sửa findings review trên commit 4ec4c0c.
Không merge vào dev. PR #1 đã được GitHub ghi nhận merge ngày 19/10/2026;
bản sửa này là commit tiếp theo trên feature/crs.

## Thay đổi

1. Audit init container dùng cùng image CRS ghim digest, chạy root trong
   container ngắn hạn network disabled/read-only root filesystem. Chỉ chuẩn
   bị thư mục/file audit cho UID 101, mode 750/640; không truncate log.
   Cả lab SQLite và MySQL chờ init hoàn tất, healthcheck kiểm tra audit ghi được.
2. Compose truyền DB_HOST/DB_PORT/DB_USER/DB_PASSWORD/DB_NAME riêng;
   DB_PASS không ghép trực tiếp vào URI. Legacy URI fallback vẫn hỗ trợ
   percent-encoding. Healthcheck MySQL quote biến password.
3. Runner MySQL ghi trạng thái running/failed/complete và completed_levels.
   Kết quả giữa chừng dùng tên partial; final CSV/JSON chỉ công bố sau khi
   mọi PL yêu cầu và export hoàn tất. JSON được thay thế atomically.

## Kiểm chứng đã thực thi

- 9 tests CRS/runner + 7 tests app/config = 16 pass.
- Failure injection cho lỗi startup PL2, Docker unavailable và CSV export:
  metadata failed, không có final summary/results; case hoàn tất có status complete.
  Đây là unit fixtures tổng hợp, không phải số liệu phát hiện/bypass WAF.
- Các mật khẩu giả chứa #, /, %, $, khoảng trắng round-trip nguyên văn trong
  config mới; legacy URI percent-encoded vẫn đọc đúng.
- Container tạm không có mạng: tạo audit có sẵn trên tmpfs root-owned 0755,
  chạy init, kiểm tra nội dung cũ còn nguyên và UID nginx ghi thêm được.
  Kết quả directory/file là 101:101 với mode 750/640.
- Cả hai Compose config hợp lệ; hai lab chạy healthy, init containers exit 0.

## Chạy lại PL1 trên Docker local

| Lab | SQLi detected/blocked | SQLi đến app | True bypass | Benign blocked |
|---|---:|---:|---:|---:|
| SQLite baseline | 5/5 | 0/5 | 0/5 | 0/8 |
| Flask/MySQL smoke | 3/3 | 0/3 | 0/3 | 0/3 |

Raw run SQLite: results/raw/crs/20261027T003042Z-3abece73/.
Raw run MySQL: results/raw/crs-integrated/20261027T003041Z-cfb9c449/.
MySQL run status complete và completed_levels=[1]. Các direct controls hợp lệ.
Phiên này không đo lại PL2/PL3; bảng PL1–PL3 cũ vẫn là lịch sử riêng.

Đối chiếu manifest SHA-256 trước sửa xác nhận 123 file raw evidence cũ không đổi.
Không commit .env hoặc raw results/logs. Coroutine/DB mocks trong tests không
thay thế phép đo MySQL thực tế. Tags Python/MySQL vẫn có thể thay đổi; đọc
metadata/image identities của từng run khi tái lập.

Lệnh tái lập: xem docs/quickstart-lab.md. Tài liệu giải thích để bảo vệ:
docs/modsecurity-walkthrough.md.
