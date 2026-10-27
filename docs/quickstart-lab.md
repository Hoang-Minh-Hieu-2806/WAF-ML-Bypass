# Quick Start — lab tích hợp trên PowerShell

Chạy từ thư mục gốc repo, Docker Desktop ở Linux containers. Runner dùng
Python standard library. Lab SQLite cũ có thể chạy đồng thời trên 18080/18081.

## Khởi động

Nếu chưa có `.env`, copy mẫu rồi đặt `DB_PASS` thành mật khẩu lab riêng.
Không ghi đè `.env` đã có; Compose truyền `DB_PASSWORD` nguyên văn từ `DB_PASS`, không ghép vào URI.
Với ký tự đặc biệt, dùng single quotes trong `.env` (giá trị mẫu): `DB_PASS='lab#only'`.
Không sửa mật khẩu của volume đã khởi tạo chỉ bằng cách sửa `.env`.

```powershell
if (-not (Test-Path -LiteralPath .env)) { Copy-Item .env.example .env }
# Lần đầu: sửa DB_PASS trong .env trước khi tạo database.
$env:CRS_PL = '1'
$env:MODSEC_RULE_ENGINE = 'On'
docker compose config --quiet
docker compose up -d --build --wait --wait-timeout 240
docker compose ps -a
```

Port mặc định: backend `127.0.0.1:8080`, CRS `127.0.0.1:8081`, ML stub
`127.0.0.1:8082`. DB không publish port. Có thêm init container `crs-audit-init` chạy một lần
với UID 0 và network disabled để đặt quyền audit cho UID 101; trạng thái
`Exited (0)` của init container là bình thường. Nó không xóa hoặc truncate log. Các port có thể đổi trong `.env`.

## Kiểm chứng

```powershell
curl.exe -i 'http://localhost:8080/healthz'
curl.exe -i 'http://localhost:8081/search?q=test'
curl.exe -i 'http://localhost:8081/product?id=1%20OR%201%3D1'
curl.exe -s 'http://localhost:8082/health'
python waf-crs/run_integrated_smoke.py
```

Kỳ vọng: health/benign 200, SQLi 403. Runner kiểm chứng thêm direct controls,
audit SQLi `942xxx`, inbound block `949110` và application evidence. Mỗi run
có snapshot/metadata/CSV/summary riêng tại `results/raw/crs-integrated/`.
Chỉ dùng kết quả khi `metadata.json` có `status=complete` và `completed_levels`
khớp `levels`. Nếu lỗi, trạng thái là `failed`, checkpoint có tên
`results.partial.json`/`summary.partial.json`; không dùng chúng làm kết quả cuối.
Đây là smoke corpus 6 case; không thay thế bảng baseline SQLite hoặc benchmark.

Khi cần chạy smoke corpus ở cả ba PL:

```powershell
python waf-crs/run_integrated_smoke.py --levels 1 2 3
```

Runner để stack ở PL cuối. Đưa về PL1 bằng `$env:CRS_PL='1'` rồi
`docker compose up -d --wait`. Không thay threshold để làm đẹp kết quả.

## Regression tests

```powershell
python -m unittest discover -s waf-crs -p "test_*.py" -v
# Test app cần Flask/PyMySQL (web-app/requirements.txt) trong Python đang dùng.
python -m unittest discover -s web-app -p test_app.py -v
```

Các test app dùng database mock; smoke runner mới kiểm chứng MySQL thật.

## Logs và dữ liệu

- WAF JSON: `logs/waf/integrated/audit.log`.
- App JSONL: `logs/application/integrated/app.jsonl`; stdout SQL vẫn có.
- `.env`, logs và raw results không commit. Không lưu Compose config đầy đủ
  hoặc container environment vào evidence vì có thể chứa mật khẩu `.env`.
- ML `/score` vẫn dùng regex stub; chưa đánh giá mô hình học máy.

## Dừng và rollback

`docker compose down` chỉ dừng/xóa container và network của stack tích hợp;
volume MySQL và các log bind mounts vẫn được giữ. Khởi động lại bằng `up -d --wait`.
Không dùng `down -v` khi cần giữ dữ liệu. Nếu volume cũ không tương thích, sao lưu
DB trước và dùng project/volume mới; không xóa volume để chữa lỗi tự động.

Lab SQLite độc lập tiếp tục dùng:

```powershell
python waf-crs/run_baseline.py --levels 1
```
