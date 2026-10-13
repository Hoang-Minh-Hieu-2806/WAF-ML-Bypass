# Architecture — T03 Lab (Owner: Hoàng Minh Hiếu)

> Lab local only. Không trỏ lab tới production.

## Tổng quan

```text
Test Generator (scripts/, ngoài lab)
        │ HTTP
        ▼
waf-crs:8081 (ModSecurity v3 + CRS 4.25.x LTS, DetectionOnly ở Phase 1)
waf-ml:8082  (FastAPI stub -> TF-IDF + LR/SVM ở Tuần 05-06)
        │ allowed
        ▼
web-app:8080 (Flask + PyMySQL -> db:3306)
        │
        ▼
db (mysql:8.4 LTS, chỉ nội bộ webnet, volume mysql-data bị ignore)
```

## Quyết định pin (2026-10)

| Thành phần | Image/base | Vì sao |
|---|---|---|
| `db` | `mysql:8.4` (LTS) | `8.0.46 đã EOL 4/2026`, chỉ vá tới 4/2027 |
| `web-app` | `python:3.11-slim + Flask==3.1.3 + PyMySQL==1.2.0` | Sync WSGI, dễ tái lập parsing discrepancy; pure-Python, nhẹ |
| `waf-ml` | `python:3.11-slim + FastAPI==0.142.2 + sklearn==1.7.1` | Typed API `{label,score}`, auto `/docs`; TF-IDF+LR/SVM đúng paper baseline |
| `waf-crs` | `owasp/modsecurity-crs:nginx` (dòng CRS v4 stable; Huy pin tag `<CRS>-nginx-<date>` 4.25.x LTS ở Tuần 03-04) | Official image, ModSec v3 bên trong; `PARANOIA=1`, `DetectionOnly` ở Phase 1 |

## Network & data

* Một net `webnet`. `db` không `ports` ra host.
* `DATABASE_URL=mysql://root:${DB_PASS}@db:3306/waf_lab` (service name `db`, không phải localhost).
* Schema/seed duy nhất được track: `docker/db/init/*.sql`. Runtime `mysql-data` bị ignore.
* Tool tấn công (`WAF-A-MoLE`, `sqlmap`, `wafw00f`) đứng ngoài lab, chạy từ `scripts/`, không thêm vào compose (xem `docs/interfaces.md`).

## Giao thức nội bộ

* `waf-crs -> web-app`: `BACKEND=http://web-app:5000`, forward nguyên query/body để so `audit.log vs app log`.
* `scripts/ -> waf-ml`: `POST /score` (xem Interfaces).
* Health: `web-app /search?q=test`, `waf-ml /health`, `db mysqladmin ping`, `waf-crs curl /search?q=test`.
