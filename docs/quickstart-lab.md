# Quick Start Lab (Owner: Hoàng Minh Hiếu)

> Chỉ chạy lab local. Không commit `.env`.

```bash
# 1. Lần đầu
cp .env.example .env
# mở .env đổi DB_PASS thành giá trị riêng

# 2. Dựng lab 4 service
docker compose up -d --build

# 3. Kiểm tra (expect waf-app, waf-crs, waf-ml, waf-db)
docker compose ps
docker compose logs -f web-app   # xem app.log stdout
docker compose logs -f waf-crs
docker compose logs -f waf-ml
docker compose logs db | tail -n 50

# 4. Smoke test benign (expect 200)
curl -i "http://localhost:8080/search?q=test"
curl -i "http://localhost:8081/search?q=test"
curl -s http://localhost:8082/health
curl -s -X POST http://localhost:8082/score \
  -H 'Content-Type: application/json' \
  -d '{"text":"test"}'

# 5. Kiểm tra DB (thay $DB_PASS bằng giá trị trong .env)
docker compose exec db mysql -uroot -p"$DB_PASS" -e "SELECT * FROM waf_lab.users;"

# 6. Dọn
docker compose down        # giữ data
docker compose down -v     # xóa cả mysql-data (seed lại từ init/)
```

## Lỗi thường gặp

| Hiện tượng | Nguyên nhân | Fix |
|---|---|---|
| `web-app` 200 nhưng `db_error` | DB chưa healthy / sai `DB_PASS` | `docker compose logs db`, kiểm tra `.env` khớp `DB_PASS` |
| `waf-crs` không 200 | `BACKEND` sai / web-app chưa healthy | `docker compose logs waf-crs`, `curl` thẳng `8080` trước |
| `mysql` restart loop | volume cũ của `8.0` còn lại | `docker compose down -v && docker compose up -d --build` |
