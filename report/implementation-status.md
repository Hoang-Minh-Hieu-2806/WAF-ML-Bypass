# Implementation Status — audit thực địa (26/10/2026)

> **Historical snapshot:** file này phản ánh trạng thái trước commit ML
> enforcement/runner mới. Trạng thái hiện hành xem `README.md`,
> `docs/architecture.md` và output của `scripts/run_experiment.py`.

> Tự sinh bởi automated agent sau khi xác minh trực tiếp (không sao chép báo cáo cũ).
> Cơ sở: `git status`, `git log`, `.gitignore`, `docs/*`, `docker-compose.yml`,
> toàn bộ `waf-ml/*.py`, `waf-crs/run_baseline.py`, `run_integrated_smoke.py`,
> corpus JSON, unit tests, và trạng thái Docker runtime.

## Bảng tổng quan

| Component | Implemented | Test status | Missing work | Evidence |
|---|---|---|---|---|
| docker-compose 4 service (web-app, waf-crs, waf-ml, db) | ✅ 4 container `Up/healthy`; ports 8080/8081/8082 chỉ bind `127.0.0.1`; DB không publish; image CRS ghim digest; healthchecks đủ | `docker compose ps` thấy 4 healthy; smoke runner 19+25/10 hoàn chỉnh | ML chưa trong đường chặn (chỉ scoring API) — enforcement path chờ review nhóm (`docs/architecture.md §ML enforcement`) | runtime check 26/10; `results/raw/crs-integrated/*/metadata.json` |
| db (MySQL 8.4, schema+seed) | ✅ `01-schema.sql`, `02-seed.sql` (users FAKE: alice/bob/admin/test/user1) | qua Thunderbird healthcheck + `SELECT 1` mỗi /healthz | — | `docker/db/init/*` |
| web-app (Flask endpoint có chủ đích vulnerable + application oracle) | ✅ `/search`,`/product`,`/login` vuln + `semantic_effect` oracle (so observed vs reference row-IDs), JSONL evidence `X-Lab-Case-ID`, cached raw body | `web-app/test_app.py` 5 test (wildcard `%`, HPP first-value-wins, login form bytes, DB-fail không tính effect) | Không có sink XSS (SQLi-only scope hiện tại) | `web-app/app.py`; `logs/application/integrated/app.jsonl` |
| waf-crs (ModSec 3.0.17 + CRS 4.30, PL1–3, audit JSON) | ✅ env `CRS_PL` điều khiển cả BLOCKING+DETECTION_PL; audit Serial JSON mount `logs/waf/integrated/audit.log`; chuyển PL bằng `docker compose up -d --wait` với env | `waf-crs/test_baseline.py`, `test_backend.py` (unittest discover); 3 evidence runs | Rule/exception chưa có; PL3 có FPR 33% (BEN-PRODUCT, rule `932350` match tên param `id`) — chưa có exclusion (đúng chủ đích: không nới để đẹp số) | `plN-effective-config.txt` từng run |
| waf-crs runner (smoke PL1–3, direct control, correlation) | ✅ `run_integrated_smoke.py`: direct control bắt buộc hợp lệ trước khi qua WAF (`semantic_effect`==intent, không sql_error); audit/app correlation; unclassified outcome → fail; update metadata từng PL. **Lưu ý: để stack ở PL cuối cùng của run** — hiện live ở PL3 | hoàn thành 3 evidence run; sau run PL3 vẫn cho stack kẹt PL3 (đã tái hiện) | Auto-return PL1 sau run (behavior đã ghi trong quickstart + runner prints) | `results/raw/crs-integrated/20261025T172523Z-cecdfdeb/` |
| ML-WAF dataset (v0, synthetic) | ✅ `build_dataset.py`: 312 mẫu deterministic (133 mal / 179 benign), 11 SQLi families + 5 benign families, dedup ổn định | chạy host OK: `n=312 malicious=133 benign=179 families=16` | chưa nhiều corpus công khai (kaggle) — kế hoạch sau giữa kỳ; không phải blocker v0 | `waf-ml/build_dataset.py` |
| ML-WAF train (TF-IDF char_wb 2–5 + LogisticRegression C=2.0) | ✅ GroupKFold 5 theo group=family (leak-safe), fit cuối với nhãn chuỗi `["benign","malicious"]`, artifacts `model.joblib` + `metrics.json` | host train cho metrics nhất quán; container đã train (26/10) | chưa có unit test riêng cho train.py (chưa blocker); metric bám confusion + per_family_detection thực tế | `waf-ml/train.py`, `/app/artifacts/metrics.json` |
| ML-WAF serving (FastAPI /score giữ contract `{label,score,model_version}`) | ✅ `server.py` train-before-import rồi set env `ML_MODEL_VERSION`; `app.py` dùng model.joblib nếu có, fallback regex stub nếu thiếu model; live trả score thật (vd UNION 0.9335) | curl verify health/score từng endpoint (26/10) | chưa có unit test riêng cho dùng-fallback (FastAPI/pydantic text="" đã tránh crash); ML chưa `block`, chỉ score | `POST /score` live |
| ML evaluation mode | ✅ mỗi case → score + label; định nghĩa "ML ≥0.5 = TP" | chưa chạy trên corpus bypass lớn (chờ runner) | cần runner tích hợp call `/score` cho từng test case (đang làm giai đoạn 4–5) | " |
| docs.interfaces.md contract cặp (params/form list-of-pairs, Label, expected_app) | ✅ schema, ownership; đã verify schema được dùng bởi corpus CRS | đọc lại toàn file (26/10) | runner chưa đọc schema này (runner mới sẽ tuân thủ) | `docs/interfaces.md §1` |
| run_experiment.py (file mới) | ❌ tại thời điểm audit • **✅ cập nhật 25/10/2026: `scripts/run_experiment.py` tồn tại** — nạp corpus 26 case, đo CRS + ML + direct control oracle, outcome classifier, evidence `results/raw/experiments/20261025T182650Z-4e5c2027/` | matrix PL1–3 chạy thành công 25/10 | ⏳ còn: re-run trên ML enforcement path sau khi chốt proxy; precision/recall per-technique | `results/tables/bypass-matrix-20261025.md` |
| corpus bypass 4 nhóm (`hpp`, `double-encoding`, `case-comment`, `parsing-discrepancy`) | ❌ chỉ `.gitkeep` tại thời điểm audit • **✅ cập nhật 25/10/2026: 26 case (11 benign + 15 malicious)** theo schema `docs/interfaces.md` | nhãn benign/malicious phản ánh đúng trong matrix PL1–3 | ⏳ mở rộng corpus công khai (kaggle) sau giữa kỳ | `dataset/bypass/*/cases.json` |
| results (bảng/chart) | ✅ SVG + bảng markdown có **(số liệu thực)** | XML valid | cần chart từ runner lớn | `results/tables/*`, `results/graphs/*` |
| README/quickstart | ✅ đã có, hướng dẫn chính xác khu $(LP) và hiện tượng cp1252 | đọc lại | [RESOLVED 2026-10-26] các câu "stub-0.1" và "F1 trên test n=312" đã được thống nhất lại theo model thật `lr-tfidf-1.0` + OOF GroupKFold5 (quickstart, `docs/interfaces.md §3`, README status) | README top |

## Inconsistency + hành động

1. **Live stack đang ở PL3** (`env BLOCKING_PARANOIA=3`) — trước demo phải `$env:CRS_PL='1'; docker compose up -d --wait`.
2. [RESOLVED 2026-10-25] Stack đã được trả về PL1 (`$env:CRS_PL='1'; docker compose up -d --wait`) và verify `tx.blocking_paranoia_level=1` trong crs-setup.conf (run `20261025T181240Z-27923299` + bypass matrix `20261025T182650Z-4e5c2027` đều chạy từ trạng thái này).
3. [RESOLVED 2026-10-26] `docs/architecture.md` đã cập nhật: model học máy thật `lr-tfidf-1.0` + OOF GroupKFold5 — không còn câu "chưa có model học máy".
4. Untracked/modified chưa commit: `M waf-ml/{app.py, Dockerfile}`, `?? waf-ml/{build_dataset,train,server}.py`, `?? report/midterm-giao-an.md` — giữ nguyên, không đụng, sẽ gom vào commit có kiểm soát (Phase 7).
5. `waf-ml/artifacts/` in-container (36KB model + metrics.json) — `.gitignore` loại trừ `*.joblib` đúng chủ đích; runner nên đọc `metrics.json` media container để log model version.
6. Smoke runner dùng dữ liệu deterministic (metadata `seed=None` là chuẩn; không có RNG vào corpus).

## Methodological constraints đã tuân thủ (recorded)

- `.gitignore` giữ `dataset/bypass/**` track được — corpus JSON sẽ được commit được, tuyệt đối `results/raw/**` và `logs/*.log` được loại trừ tự động (không cần thêm rule).
- `/healthz` không chứa input SQL; các healthcheck không được tính vào corpus.
- Không thêm exclusion CRS chỉ để giảm FPR "đẹp số" — nếu nhóm quyết dùng exclusion phải công bố riêng kèm trade-off.
