# Quick Start — lab tích hợp trên PowerShell

Chạy từ thư mục gốc repo, Docker Desktop ở Linux containers. Runner dùng
Python standard library. Lab SQLite cũ có thể chạy đồng thời trên 18080/18081.

## Khởi động

Nếu chưa có `.env`, copy mẫu rồi đặt `DB_PASS` thành mật khẩu lab riêng.
Không ghi đè `.env` đã có; `DATABASE_URL` tham chiếu cùng `DB_PASS`.

```powershell
if (-not (Test-Path -LiteralPath .env)) { Copy-Item .env.example .env }
# Lần đầu: sửa DB_PASS trong .env trước khi tạo database.
$env:CRS_PL = '1'
$env:MODSEC_RULE_ENGINE = 'On'
# Bắt buộc nếu đường dẫn repo chứa ký tự ngoài cp1252 (ví dụ "Bảo mật web và app"):
# runner Python < 3.15 crash ở bước in path khi console Windows dùng cp1252.
$env:PYTHONUTF8 = '1'
docker compose config --quiet
docker compose up -d --build --wait --wait-timeout 240
docker compose ps
```

Port mặc định: backend `127.0.0.1:8080`, CRS `127.0.0.1:8081`, ML enforcement
`127.0.0.1:8082`. DB không publish port. Các port có thể đổi trong `.env`.

## Kiểm chứng

```powershell
curl.exe -i 'http://localhost:8080/healthz'
curl.exe -i 'http://localhost:8081/search?q=test'
curl.exe -i 'http://localhost:8081/product?id=1%20OR%201%3D1'
curl.exe -s 'http://localhost:8082/health'
echo '{"text":"1 OR 1=1"}' | curl.exe -s -X POST http://localhost:8082/score -H "Content-Type: application/json" -d "@-"
curl.exe -i 'http://localhost:8082/search?q=laptop'
curl.exe -i 'http://localhost:8082/product?id=1%20OR%201%3D1'
python waf-crs/run_integrated_smoke.py
# So sánh end-to-end CRS-only/ML-only trong cùng run:
python scripts/run_experiment.py --levels 1 2 3
# Run riêng chuỗi hybrid CRS -> ML -> app:
python scripts/run_experiment.py --crs-backend ml --levels 1 2 3
```

Kỳ vọng: CRS health/benign 200 và SQLi 403; ML `/score` trả score của
`lr-tfidf-1.0`; ML enforcement cho benign qua backend và trả 403 cho SQLi.
Runner `scripts/run_experiment.py` kiểm chứng thêm direct controls,
audit SQLi `942xxx`, inbound block `949110` và application evidence. Mỗi run
có snapshot/metadata/CSV/summary riêng tại `results/raw/crs-integrated/`.
Đây là smoke corpus 6 case; không thay thế bảng baseline SQLite hoặc benchmark.

Khi cần chạy smoke corpus ở cả ba PL:

```powershell
python waf-crs/run_integrated_smoke.py --levels 1 2 3
```

Runner để stack ở PL cuối. Đưa về PL1 bằng `$env:CRS_PL='1'` rồi
`docker compose up -d --wait`. Không thay threshold để làm đẹp kết quả.

## Regression tests

```powershell
python -m unittest discover -s waf-crs -p test_baseline.py -v
# Test app cần Flask/PyMySQL (web-app/requirements.txt) trong Python đang dùng.
python -m unittest discover -s web-app -p test_app.py -v
```

Các test app dùng database mock; smoke runner mới kiểm chứng MySQL thật.

## Logs và dữ liệu

- WAF JSON: `logs/waf/integrated/audit.log`.
- ML JSONL: `logs/waf-ml/integrated/ml.jsonl`.
- App JSONL: `logs/application/integrated/app.jsonl`; stdout SQL vẫn có.
- `.env`, logs và raw results không commit. Không lưu Compose config đầy đủ
  hoặc container environment vào evidence vì có thể chứa mật khẩu `.env`.
- ML `/score` chạy model lr-tfidf-1.0 (train thật trong container); đánh giá n=312 GroupKFold5: F1 0.9076, FPR 1.68% — results/tables/ml-v0-summary.md.

## Dừng và rollback

`docker compose down` chỉ dừng/xóa container và network của stack tích hợp;
volume MySQL và các log bind mounts vẫn được giữ. Khởi động lại bằng `up -d --wait`.
Không dùng `down -v` khi cần giữ dữ liệu. Nếu volume cũ không tương thích, sao lưu
DB trước và dùng project/volume mới; không xóa volume để chữa lỗi tự động.

Lab SQLite độc lập tiếp tục dùng:

```powershell
python waf-crs/run_baseline.py --levels 1
```
