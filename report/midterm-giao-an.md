# T03 — Giáo án báo cáo giữa kỳ

> **Đề tài:** T03 — WAF học máy và kỹ thuật né tránh: tái lập tấn công đối kháng
> **Chương:** C4 (WAF bypass) · C5 — **Độ khó:** ★★★
> **Nhóm 5 thành viên:** Hoàng Minh Hiếu, Châu Gia Huy, Đặng Văn Hoàng, Lê Đình Long, Huỳnh Như Hoàng
> **Số slide đề xuất:** 14 — **Thời lượng:** 10–12 phút trình bày + demo 5 phút + QA

---

## PHẦN 1 — TÓM TẮT Ý TƯỞNG (slide 1–3, ~2 phút)

### 1.1. Đặt vấn đề

**WAF (Web Application Firewall)** là lớp phòng thủ lớp 7 phổ biến nhất. Có hai hướng tiếp cận:

- **Signature-based** (ModSecurity + **OWASP CRS** – Core Rule Set): khớp pattern/mã hóa đã biết.
- **ML-based** (Machine Learning): học từ corpus labeled, phân loại request thành malicious/benign.

Cả hai đều có thể bị **vượt qua (bypass)** bằng phép biến đổi payload mà **WAF và ứng
dụng diễn giải khác nhau**. Điểm mấu chốt: payload chỉ là chuỗi byte; "ý nghĩa" của
nó là một **hàm của parser** đọc nó. Khi `WAF parser ≠ App parser`, cái WAF nhìn thấy
không phải là cái ứng dụng thực thi — đây là cơ chế gốc của bypass (cốt lõi của
nghiên cứu WAFFLED, ACSAC 2025 — điểm cộng rõ ràng nếu nhóm nắm và chứng minh được).

### 1.2. Ý tưởng đồ án

Dựng một **lab local 4 service** (Docker): Client → WAF signature (ModSecurity
v3 + CRS 4.30) → Web App Flask cố tình vulnerable (Flask + PyMySQL + MySQL
8.4); song song đó, một **WAF ML** ở dạng scoring API (TF-IDF + Logistic
Regression — đã chốt `lr-tfidf-1.0`, chưa làm đường chặn). Sau đó:

1. Chạy bộ **baseline SQLi/benign** (SQLi = SQL Injection) để đo hiệu suất gốc của từng WAF và False
   Positive theo Paranoia Level (PL) 1→2→3;
2. Áp **4 nhóm kỹ thuật né tránh** trong giáo trình C4 — HPP (HTTP Parameter
   Pollution) / Fragmentation,
   Double Encoding, Case Variation + SQL Comment, Parsing Discrepancy — tái lập
   theo bài báo công khai (WAF-A-MoLE, AdvSQLi) chỉ trên lab của nhóm;
3. Đo **bypass rate theo từng nhóm kỹ thuật**, so sánh **CRS vs ML**;
4. Với mỗi bypass thành công, **giải thích cơ chế gốc** (khác biệt decode/parse),
   không dừng ở liệt kê payload;
5. Đưa ra **khuyến nghị cấu hình CRS (Paranoia Level + exception hẹp)** dựa trên
   dữ liệu thực nghiệm.

### 1.3. Phạm vi và đạo đức nghiên cứu

- **Trong phạm vi:** lab local, hệ thống do nhóm kiểm soát 100%, port chỉ bind
  `127.0.0.1`, DB không expose ra host, seed dữ liệu giả.
- **Ngoài phạm vi:** không tấn công WAF thương mại / WAF-as-a-Service production,
  không hệ thống bên thứ ba (đích đến luôn là `localhost`).
- Đã công khai cam kết trong README + SECURITY.md của repo.

### 1.4. Câu hỏi nghiên cứu (RQ)

| RQ | Nội dung |
|---|---|
| RQ1 | WAF signature vs ML hiệu quả thế nào trước mutated payload? |
| RQ2 | Kỹ thuật né tránh nào đạt bypass rate cao nhất trong lab? |
| RQ3 | Encoding / parameter handling / khác biệt parser tác động ra sao? |
| RQ4 | Tăng CRS Paranoia Level ảnh hưởng detection vs FPR thế nào? |
| RQ5 | Nguyên nhân gốc của bypass thành công là gì (khác biệt parser)? |

---

## PHẦN 2 — TIẾN ĐỘ HIỆN TẠI (slide 4, ~1 phút): NHÓM ĐÃ LÀM ĐƯỢC GÌ

Map theo roadmap 12 tuần (tuần 1 bắt đầu 28/09/2026; hiện đang ở **tuần 05**):

| Giai đoạn | Trạng thái | Bằng chứng trong repo |
|---|---|---|
| T01–02: Lab Docker 4 service | ✅ Hoàn thành 13/10 (milestone đúng hạn) | commit `0c1397`; `docker compose ps` → 4 container healthy |
| T03–04: ModSecurity+CRS & Baseline | ✅ Hoàn thành 10/10 (lab SQLite PL1–3) + 18/10 (tích hợp Flask/MySQL) | `report/waf-crs-baseline.md`, `report/crs-docker-integration.md`, raw evidence `results/raw/crs*/*` |
| T05–06: ML-WAF pipeline & model | ✅ **Train + serving xong 25/10**: dataset 312 mẫu tự sinh, TF-IDF/LogReg, OOF GroupKFold5 theo family (F1 90.76%/FPR 1.68%), `lr-tfidf-1.0` chạy thật trong `/score` (7/7 probe khớp). Còn: mở rộng corpus + review nhóm. | `waf-ml/train.py`, `waf-ml/server.py`, `results/tables/ml-v0-summary.md`, container `/app/artifacts/metrics.json` |
| — ML enforcement proxy (bổ sung sau T05–06) | ✅ **Merge 26/10/2026** từ `feature/ml-enforcement-report-audit`: route `/search /product /login` trên `:8082` chấm score → block 403 / forward raw; evidence JSONL + header `X-ML-Decision/Score` | `waf-ml/app.py`, `docker-compose.yml` (`ML_THRESHOLD`, `ML_BACKEND`), `docs/architecture.md` |
| T07–08: HPP & Double-Encoding | ✅ **25/10 — trước kế hoạch:** corpus (3 ben + 3 mal HPP; 2 ben + 4 mal DE), runner, matrix PL1–3; phần "ML chặn" giờ đo được end-to-end qua proxy (hybrid CRS → ML → app) | `dataset/bypass/hpp/cases.json`, `dataset/bypass/double-encoding/cases.json`, `results/tables/bypass-matrix-20261025.md` |
| T09: Case Variation + SQL Comment | ✅ **25/10:** 3 ben + 5 mal; CRS bắt 100% mọi PL (libinjection `942100` không phân biệt hoa-thường + `942270`) | `dataset/bypass/case-comment/cases.json` |
| T10: Parsing Discrepancy | ✅ **25/10:** 3 ben + 3 mal; CRS chặn hết qua rule transport (920640/920170/920420) — **chưa đạt case true_bypass (kết quả âm có giá trị)** | `dataset/bypass/parsing-discrepancy/cases.json` |
| T11: Tổng hợp & phân tích | 🔶 Sơ bộ: matrix PL1–3 + bảng per-technique + 4 SVG + bảng CRS/ML/hybrid **đã tái lập độc lập post-merge** (runs `2af841ab`, `4e4a7f2d`, commit `661aed6`); còn precision/recall per-technique và rule hotlist | `results/tables/*`, `results/graphs/*` |
| T12: Hardening & báo cáo | 🔶 Sơ bộ — phân tích FP PL2/PL3 đã có; khuyến nghị exception chưa viết | mục FP trong `report/waf-crs-baseline.md` |

**Ước tính tổng tiến độ: ~65% kế hoạch 12 tuần** — kết quả thực nghiệm (corpus 4 nhóm
+ runner + matrix PL1–3) hoàn tất trước kế hoạch ~2 tuần; ML enforcement proxy
đã merge; phần còn lại chủ yếu là phân tích sâu (per-technique, hybrid end-to-end)
và hardening.

### Kết quả giữa kỳ — bảng tóm tắt có bằng chứng

**A. CRS baseline trên backend thật (smoke 6 case × 3 PL** — run
`20261025T172523Z-cecdfdeb`, bảng chi tiết: `results/tables/pl-summary-20261025.md`):

| PL | SQLi detected | SQLi blocked | True bypass | Benign blocked (FPR) |
|---|---|---|---|---|
| 1 | 3/3 (100%) | 3/3 (100%) | 0/3 | 0/3 (0%) |
| 2 | 3/3 (100%) | 3/3 (100%) | 0/3 | 0/3 (0%) |
| 3 | 3/3 (100%) | 3/3 (100%) | 0/3 | 1/3 (33.3% — `932350` match **tên tham số** `id`) |

**B. Bypass matrix SQLi evasion (26 case = 11 benign + 15 malicious × 3 PL = 78 lượt** — run
`20261025T182650Z-4e5c2027`, bảng chi tiết: `results/tables/bypass-matrix-20261025.md`):

| Metric (trên 15 malicious / 11 benign) | PL1 | PL2 | PL3 |
|---|---|---|---|
| **SQL-family detection** (có rule `942xxx`) | 11/15 (73.3%) | 11/15 (73.3%) | 11/15 (73.3%) |
| **Tổng malicious bị block** | 13/15 (86.7%) | 13/15 (86.7%) | 15/15 (100%) |
| — trong đó chỉ nhờ rule protocol (không có rule SQLi) | 2 (920640/920420) | 2 | 4 (+ de-mal-002/003 nhờ 920230+920272) |
| **Benign bị block (FPR)** | 1/11 (9.1%) | 1/11 (9.1%) | 8/11 (72.7%) |
| **True bypass** (oracle semantic) | 0/15 | 0/15 | 0/15 |
| `pass_without_effect` (WAF pass, app không thực thi) | 2/15 | 2/15 | 0/15 |
| ML classifier `lr-tfidf-1.0` (scoring, `score ≥ 0.5` = malicious) | TP 15/15, FP 0/11 | TP 15/15, FP 0/11 | TP 15/15, FP 0/11 |

Đọc bảng: **SQL-family recall (detected) ≠ tổng block**. 13/15 = 86.7% chỉ là tỷ lệ
CRS chặn tổng; ở PL3 sự tăng chặn đến từ rule protocol (920230/920272/921180/949110)
chứ không phải phát hiện thêm payload SQL — chính cơ chế này đẩy FPR benign lên 72.7%.

**C. ML model `lr-tfidf-1.0` — OOF validation (GroupKFold 5-fold group=family, n=312)** —
chi tiết: `results/tables/ml-v0-summary.md`; artifact container `/app/artifacts/metrics.json`:

| Metric | Giá trị | Ghi chú |
|---|---:|---|
| Accuracy / Precision (malicious) / Recall | 92.63% / 97.41% / 84.96% | confusion **TN 176 · FP 3 · FN 20 · TP 113** |
| **F1 / FPR / FNR / AUROC** | **0.9076 / 1.68% / 15.04% / 0.9757** | FPR = 3/179 benign bị nhãn malicious |
| Điểm yếu per-family | stacked 40%, boolean 55.6% | families nhỏ (5–8 mẫu/family) |

Số liệu ML là **out-of-fold (OOF) validation** bằng GroupKFold 5-fold gộp theo
family — **không phải** kết quả trên một held-out test set độc lập. Model serving
cuối cùng được fit trên toàn bộ n=312; corpus nhỏ, tự sinh nên chỉ chứng minh
pipeline đúng, không phải benchmark production và **không so sánh trực tiếp 1-1
với CRS** (khác protocol đo, tập mẫu và cách tính FPR).

**D. ML enforcement + hybrid end-to-end (26/10 — post-merge, threshold 0.5)** —
run tự tái lập `20261026T100537Z-2af841ab` (CRS/ML-only) +
`20261026T100617Z-4e4a7f2d` (hybrid), commit `661aed6`; bảng chi tiết:
`results/tables/ml-enforcement-matrix-20261026.md`:

| Đường | PL1 block | PL2 block | PL3 block | FPR (9.1/9.1/72.7%) | True bypass |
|---|---:|---:|---:|---|---:|
| CRS-only | 13/15 (86.7%) | 13/15 | 15/15 | 1/1/8 trên 11 benign | 0/15 |
| ML-only | 15/15 (100%) | 15/15 | 15/15 | **0/11 mọi PL** | 0/15 |
| Hybrid CRS→ML | 15/15 | 15/15 | 15/15 | kế thừa CRS | 0/15 |

Đọc bảng: hybrid giữ FPR của CRS (lớp CRS phía trước quyết định FP — PL3 72.7%
không sửa được) nhưng vá được 2 case DE mà CRS cho qua không effect
(`de-mal-002/003`, score 0.6295/0.6184, `blocking_layer="ml"`). ML-only là
thế mạnh precision — FP 0/11, nhưng chỉ đánh giá model trên projection
query/form của corpus này, chưa phải external holdout. Threshold sweep
(0.30–0.80) trong bảng matrix; 0.5 tốt nhất trên corpus nhỏ này, chưa kết luận
cho production.

---

## PHẦN 3 — CÁC TÍNH NĂNG CHÍNH CỦA SẢN PHẨM (slide 5–7, ~2 phút)

1. **Lab 4 service tái lập được (reproducible)**: Docker Compose ghim image
   digest, healthcheck từng service, `.env.example` tách secret, evidence run có
   run-ID + SHA-256 source/corpus — kết quả lần nào cũng dựng lại được.
2. **Web App mục tiêu có chủ đích vulnerable** (3 endpoint): `GET /search?q=`,
   `GET /product?id=`, `POST /login` — ghép chuỗi SQL để CRS có việc làm, nối
   PyMySQL → `waf_lab.users` MySQL 8.4.
3. **Oracle đối chứng trực tiếp (direct control)**: cùng một request được gửi
   qua 2 đường: trực tiếp vào backend (`:8080`) và qua WAF (`:8081`), cùng
   correlation ID `X-Lab-Case-ID`. Backend chạy thêm query tham chiếu dùng
   bind-parameter trên cùng connection; nếu handler trả nhiều row ID hơn tập
   tham chiếu thì `semantic_effect=true`. Nhờ vậy phân biệt được 4 trạng thái:
   chặn / cho qua / nhìn thấy (detected) / bypass thật. Đây là tính năng quan
   trọng nhất về **phương pháp luận**: không coi "HTTP 200" là bypass.
4. **WAF Signature đầy đủ evidence**: ModSecurity v3 blocking, audit JSON Serial
   (`942xxx` = SQLi detect, `949110` = chặn), PL 1/2/3 thông qua biến `CRS_PL`.
5. **ML scoring + enforcement — model học máy thật (25/10)**: `POST /score {"text"} →
   {"label","score","model_version"}` giờ trả nhãn từ **TF-IDF + LogisticRegression
   `lr-tfidf-1.0`** train ngay trong container (OOF GroupKFold5 theo family:
   F1 90.76%/FPR 1.68% — không phải held-out test set); regex stub chỉ còn
   fallback nếu image thiếu model. Từ 26/10/2026 các route ứng dụng trên `:8082`
   là **enforcement proxy**: `score ≥ ML_THRESHOLD` (mặc định 0.5) → 403 không
   chạm backend, ngược lại forward nguyên raw query/body — có `X-ML-Decision`,
   `X-ML-Score` và JSONL evidence tại `logs/waf-ml/integrated/ml.jsonl`.
6. **Schema test-case JSON chuẩn hóa** (điều kiện để biểu diễn HPP): `params`/`form` là
   **danh sách cặp có thứ tự**, giữ nguyên duplicate key — yêu cầu bắt buộc để
   biểu diễn HPP/parsing discrepancy (JSON object không được).
7. **Pipeline automation — đã có (25/10), mở rộng 26/10**: `scripts/run_experiment.py`
   nạp corpus 26 case → gửi qua 2 đường (direct control + qua WAF) → thu CRS
   decision (audit correlation) + ML decision + app behavior cùng run-ID →
   outcome classifier (`blocked / allowed / allowed_detected / pass_without_effect /
   true_bypass / benign_blocked / control_invalid / incomplete`) →
   `results.json|csv` + `summary.json` + metadata fingerprint trong thư mục
   evidence riêng từng run. Ba chế độ: CRS-only, ML-only,
   hybrid `CRS → ML → web-app` (`--crs-backend ml`), thêm `sweep_thresholds.py`.
8. **Tính bảo mật của chính lab**: không secret committed, không dataset raw,
   port loopback, tool tấn công (sqlmap/WAF-A-MoLE) nằm ngoài image compose.

---

## PHẦN 4 — MÔ HÌNH TRIỂN KHAI (slide 8–9, ~2 phút)

### 4.1. Kiến trúc hiện tại (đã chạy thật)

```text
                     ┌────────────┐   Client/host (localhost)
                     │ Python CLI │   waf-crs/run_integrated_smoke.py
                     └──┬───────┬─┘   curl.exe
                        │       │
        :8080 trực tiếp │       │ :8081
        (direct control)│       │(qua WAF)
                        ▼       ▼
              ┌──────────────┐ ┌────────────────────────────┐
              │   web-app    │ │  waf-crs (nginx)           │
              │ Flask+PyMySQL│ │  ModSec v3.0.17 + CRS 4.30 │
              │ :5000        │ │  :8080  PL=CRS_PL (1/2/3)  │
              └──────┬───────┘ └───────┬────────┬───────────┘
                     │                 │        │ audit JSON
                     ▼                 │        ▼
              ┌──────────────┐         │  logs/waf/integrated/audit.log
              │  db (MySQL)  │         │
              │ 8.4 waf_lab  │         │  logs/application/integrated/app.jsonl
              │ nội bộ webnet│         ▼
               └──────────────┘   waf-ml :8082 (FastAPI) — scoring + enforcement
                                  /score giữ contract; route app block/forward
```

- Mạng Docker bridge `waf-lab-webnet`; **chỉ HTTP ports bind loopback**, DB
  không publish; request source luôn là machine của nhóm.
- Log song song cùng correlation ID: audit WAF ↔ app evidence JSONL
  (`raw_target`, `parsed_pairs`, SQL, `row_ids`, `reference_row_ids`,
  `semantic_effect`, `http_status`).
- **waf-ml giờ nằm trong luồng request tùy cấu hình** (merge 26/10/2026):
  mặc định compose forward `waf-crs → web-app:5000` (CRS-only); cấu hình hybrid
  `CRS → ML → web-app` qua `--crs-backend ml`; độc lập đó client gọi `/score`
  trên `:8082` để evaluation/so sánh. Sản phẩm hiện có **ML scoring độc lập**
  và **proxy enforcement nhất quán block/forward** (chi tiết mục 4.2).

### 4.2. Đường xử lý ML và hybrid (đã triển khai — slide 9)

`waf-ml` hiện là proxy enforcement: `score < ML_THRESHOLD` thì forward nguyên
raw query/body tới web-app, ngược lại trả 403 và ghi evidence JSONL. `/score`
vẫn giữ contract cũ. Runner đo đồng thời CRS-only và ML-only; tùy chọn
`--crs-backend ml` dựng chuỗi hybrid `CRS → ML → web-app`.

Run 26/10: có 2 nguồn — run gốc của ĐVH (evidence raw trên máy anh; see
`results/tables/ml-enforcement-matrix-20261026.md`) và **bản tái lập độc lập
post-merge trên máy Hiếu cùng commit `661aed6`**: CRS/ML-only
`20261026T100537Z-2af841ab`, hybrid `20261026T100617Z-4e4a7f2d` — mọi số
khớp chính xác. Mỗi run 26 case × 3 PL, không có incomplete hoặc invalid control.

| Cấu hình | PL1 block/FPR | PL2 block/FPR | PL3 block/FPR | True bypass |
|---|---:|---:|---:|---:|
| CRS-only | 13/15 · 9.1% | 13/15 · 9.1% | 15/15 · 72.7% | 0/15 |
| ML-only, threshold 0.5 | 15/15 · 0% | 15/15 · 0% | 15/15 · 0% | 0/15 |
| Hybrid CRS→ML | 15/15 · 9.1% | 15/15 · 9.1% | 15/15 · 72.7% | 0/15 |

Latency PL1 trên một lượt 26 case (chỉ mô tả run này, chưa phải benchmark tải):
CRS p50/p95 = 26.249/37.706 ms; ML p50/p95 = 18.114/46.284 ms; hybrid
p50/p95 = 13.852/40.577 ms.

### 4.3. Phân công theo module

| Thành viên | Module | Hiện trạng |
|---|---|---|
| Hiếu | docker-compose, Dockerfiles, DB init, docs | ✅ xong, hợp khối |
| Huy | ModSecurity + CRS (PL1–3, audit) | ✅ baseline + evidence xong |
| Đặng Văn Hoàng | waf-ml (dataset, TF-IDF+LR, API + enforcement proxy) | ✅ lr-tfidf-1.0 train + serving xong 25/10 (OOF GroupKFold5: F1 90.76%, FPR 1.68%); enforcement proxy merge 26/10 (block/forward + evidence JSONL); còn mở rộng corpus + review nhóm |
| Long | test-case 4 kỹ thuật bypass | ✅ 25/10: corpus 26 case (schema `docs/interfaces.md` §1, có ben/mal đủ 4 nhóm + transport/control extension) |
| Huỳnh Như Hoàng | run_experiment.py + metrics + chart | ✅ 25/10: runner + matrix PL1–3 + bảng/SVG; 26/10: hỗ trợ thêm CRS-only/ML-only/hybrid + `sweep_thresholds.py`; còn precision-recall per-technique + rule hotlist |

---

## PHẦN 5 — CÁC KỊCH BẢN DEMO (slide 10–14)

> Chia 2 loại: **Demo sống** trên lab đã dựng (A–D) và **Demo bằng slide/
> bộ test-case** (E — kịch bản trình bày; phần tương ứng đã chạy 25/10).
> Các kịch bản mục PHẦN 5 là **speaker notes/demo script**, tách khỏi nội dung
> báo cáo. Demo A–E đều có code/corpus chạy thật; không gọi payload bên ngoài lab.

### Demo A — Dựng lab 4 service (2 phút)

```powershell
docker compose ps                      # 4 container: waf-app / waf-crs / waf-ml / waf-db healthy
curl.exe -i "http://localhost:8080/healthz"   # 200 (health endpoint không mang input SQL)
```

Kể câu chuyện reproducibility: image ghim digest + `--wait healthcheck`.

### Demo B — CRS chặn SQLi (3 phút)

```powershell
# 1) benign -> 200
curl.exe -i "http://localhost:8081/search?q=test"

# 2) SQLi -> 403
curl.exe -i "http://localhost:8081/product?id=1%20OR%201%3D1"

# 3) chỉ audit cho thấy quy luật: rule SQLi 942100 + chặn 949110
Get-Content logs\waf\integrated\audit.log -Tail 5
```

Điểm nhấn: "**403**" là kết quả; "**cơ chế**" nằm trong audit: ModSec decode URL
một lần → `ARGS:id = 1 OR 1=1` → libinjection `942100` → điểm anomaly ≥ 5 →
`949110` chặn. Đây chính là pipeline mà các kỹ thuật bypass sẽ cố phá.

### Demo C — WAF vs App trên backend thật — oracle phương pháp (3 phút)

```powershell
$env:PYTHONUTF8 = '1'
python waf-crs/run_integrated_smoke.py --levels 1 2 3
# → results/raw/crs-integrated/<run-id>/results.csv  (run mới 26/10:
#   20261025T172523Z-cecdfdeb — PL1 100%/FPR 0%, PL3 FPR 33.3% rule 932350)
```

Mở `results.csv` chỉ ra từng cột:

- `waf_decision` (blocked/allowed) — quyết định CRS;
- `detected` — có rule `942xxx` (nhìn thấy chứ chưa chắc chặn);
- `reached_app` — request đã tới backend chưa;
- `semantic_effect` — backend trả row-ID nằm ngoài tập query tham chiếu;
- `true_bypass` = malicious + allowed + **không** detected + semantic effect.

Điểm nhấn chuẩn bị cho bypass: "**chúng tôi không tính 'HTTP 200' là bypass**".
Đây là lý do khách quan của thí nghiệm.

### Demo D — ML-WAF model thật `/score` (2 phút)

```powershell
curl.exe -s http://localhost:8082/health
# → {"status":"ok","model_version":"lr-tfidf-1.0"}   (không còn stub-0.1)

# SQLi qua mutation → malicious với xác suất thật:
echo '{"text":"-1 UNION SELECT id,username FROM users"}' | curl.exe -s -X POST http://localhost:8082/score -H "Content-Type: application/json" -d "@-"
# → {"label":"malicious","score":0.93,...}
# benign tiếng Việt UTF-8 → benign mạnh (giống FP PL3 của CRS mà ML phát hiện tốt):
echo '{"text":"màn hình laptop 450"}' | ...   # → {"label":"benign","score":0.0727}

# Boundary case — ví dụ cộng thêm về threshold (0.5):
#   "admin' -- #" → {"label":"malicious","score":0.5057}
#   (score sát ngưỡng — câu chuyện về trade-off threshold của classifier)

# Enforcement thật: benign được forward, SQLi bị ML trả 403
curl.exe -i "http://localhost:8082/search?q=laptop"
curl.exe -i "http://localhost:8082/product?id=1%20OR%201%3D1"
```

Kể câu chuyện (3 nhịp, 45 giây):
1. *"Model TF-IDF + LogReg được train trong container bằng sklearn pin sẵn,
   dataset tự sinh 312 mẫu, GroupKFold theo family nên mutation 'anh em' không
   được pha trộn giữa train/test"* — F1 90.76% là **OOF validation (không phải
   held-out test set)**; 20 miss do corpus nhỏ; model serving fit trên toàn bộ 312.
   Độ phủ corpus nhỏ là giả thuyết cần external holdout kiểm chứng.
2. *"Per-family cho thấy ML yếu ở stacked (40%) / boolean (55.6%)"* — cơ hội
   cho tuần 07: corpus công khai (Kaggle SQLi 40k) + mutation WAF-A-MoLE.
3. Bảng/chart phục vụ: `results/tables/ml-v0-summary.md`
   + `results/graphs/waf-ml-family-detection.svg` + `results/graphs/pl-fpr-detection.svg`.

### Demo E — CORPUS 4 kỹ thuật bypass (đã chạy 25/10 — Bản slide)

Bộ test-case cho `dataset/bypass/<technique>/cases.json` (Long sở hữu):

| Kỹ thuật | Payload mẫu | Cơ chế gốc (chiều WAF ≠ App) | Kỳ vọng đo lường |
|---|---|---|---|
| **HPP** | `/product?id=1 OR 1=1&id=5` | WAF duyệt từng occurrence của `ARGS:id`; Flask `request.args.get()` lấy **giá trị đầu tiên** | Payload đầu có semantic effect ở direct control; đo WAF trên chính parser của stack này |
| **Double Encoding** | `/search?q=%2527%2520OR%25201%253D1` (×2 decode → `' OR 1=1`) | WAF lưu ARGS sau **1 lượt decode**; CRS thêm transform `t:urlDecodeUni` theo từng rule nên nhiều payload double-encoded vẫn bị bắt — cần đo chính là điều này; App chỉ "thấy" `'` nếu code chủ động decode lần 2 (`unquote(unquote())`) | Chỉ tính bypass khi direct control có semantic effect; "không bypass" trên stack này cũng là một phát hiện (kết quả phủ định có giá trị) |
| **Case + Comment** | `-1 UnIoN/**/sElEcT/**/id,usER/**/FrOm/**/users--` | case/comment cố thay đổi ranh giới token; libinjection vẫn bắt toàn bộ 5 malicious case hiện tại | Kết quả phủ định: 5/5 bị rule `942xxx` phát hiện |
| **Parsing Discrepancy** | chunked form, GET-with-body, Content-Type mismatch | WAF và Flask có thể chọn processor/policy khác nhau | CRS chặn bằng rule transport; corpus hiện chưa có true bypass và chưa thử trailer header |

Quy tắc bảo toàn kết quả: mỗi case luôn chạy 2 đường (direct + qua WAF) và
phải có `semantic_effect=true` ở direct control trước — không chấp nhận
"bypass" chỉ vì `HTTP 200`.

**Cập nhật 26/10:** corpus 26 case được chạy qua ML enforcement/hybrid —
run gốc của ĐVH + bản tái lập độc lập post-merge (commit `661aed6`):
CRS/ML-only `20261026T100537Z-2af841ab`, hybrid `20261026T100617Z-4e4a7f2d`,
mọi số khớp chính xác từng ô (bảng: `results/tables/ml-enforcement-matrix-20261026.md`).
Kết quả PL1–3: bypass thật 0/15 mọi PL; CRS block 13/15 ở PL1–2 và 15/15 ở PL3; FPR
benign 9.1% → 9.1% → **72.7%** (PL3 over-block bằng rule protocol 920230/920272/921180
chứ không phải SQL-family); 2 case DE `pass_without_effect` ở CRS-only (CRS decode 1 lượt —
kết quả phủ định có giá trị đúng như bảng trên dự đoán) và được hybrid ML chặn
ở PL1–2 (score 0.6295/0.6184, `blocking_layer="ml"`).

### Q&A dự phòng (chuẩn bị trước)

- *"Vì sao CRS bắt được SQLi này — là khớp chuỗi không?"* → Không: `942100` là libinjection (SQL tokenization), `949110` là ngưỡng anomaly tổng hợp.
- *"Request qua WAF không để lộ gì?"* → DB không publish port, HTTP chỉ bind `127.0.0.1`, seed user giả trong lab, không có dữ liệu thật.
- *"Có dùng WAF-A-MoLE / sqlmap không?"* → Có, chỉ nhắm mục tiêu lab do nhóm kiểm soát (`scripts/requirements-attack.txt`, không cài vào image compose).
- *"PL3 FPR BEN-PRODUCT là chuyện gì?"* → Rule `932350` match **tên tham số** `id` (trùng tên lệnh Unix `id`), không nâng giá trị `1`. FPR 33% → hardening cần exception hẹp theo endpoint/param, có evidence.
- *"ML đã chặn request chưa?"* → **Có, từ 26/10/2026** — enforcement proxy trên
  `:8082` chấm mọi route ứng dụng: `score ≥ ML_THRESHOLD` (0.5 mặc định) → 403
  không chạm backend, else forward nguyên raw. `/score` vẫn là contract cũ cho
  evaluation; trong bypass matrix 25/10 ML nhãn chạy evaluation-only: TP 15/15, FP 0/11.
- *"Số F1 90.76% đo trên tập nào?"* → OOF validation GroupKFold 5-fold theo family trên n=312 — **không phải held-out test set độc lập**; model serving fit trên toàn bộ 312; corpus tự sinh nhỏ nên không claim production readiness.
- *"Vì sao không so sánh trực tiếp CRS vs ML cùng bảng?"* → Protocol khác nhau: CRS đo end-to-end qua đường chặn (block + audit), ML chỉ đo classifier trên string (`score ≥ 0.5`); tập mẫu/định nghĩa FPR khác nhau → chỉ so ở tầng khái niệm, không gộp số.

---

## PHẦN 6 — CÔNG VIỆC TIẾP THEO (KẾ CHẾ VỀ SAU GIỮA KỲ)

| Tuần | Công việc | Owner | Đầu ra |
|---|---|---|---|
| 05–06 (✅ 25/10) | Dataset SQLi/benign → TF-IDF + LR → thay stub `/score` (giữ nguyên contract) — `lr-tfidf-1.0` F1 90.76%/FPR 1.68%, train-in-container | Đặng Văn Hoàng | `waf-ml/train.py` + `results/tables/ml-v0-summary.md` |
| 05–06 (✅ 26/10) | Review cơ chế ML enforcement proxy (option 1) | Hiếu + ĐVH + Huỳnh | ✅ 26/10: proxy block/forward + evidence JSONL merge từ `feature/ml-enforcement-report-audit`; runner hỗ trợ CRS-only/ML-only/hybrid |
| 07–08 | `run_experiment.py` + corpus HPP + double-encoding; chạy trên CRS **và** ML | Long + Huỳnh | ✅ 25/10: runner + corpus 26 case + matrix PL1–3 (bypass 0, FPR PL3 72.7%); ✅ 26/10: đo lại trên **ML enforcement path** (CRS/ML-only/hybrid — runs `2af841ab`, `4e4a7f2d`, commit `661aed6`) |
| 09 | corpus case/comment | Long | ✅ 25/10: 3 ben + 5 mal (cc-mal-004 fixed payload → effect true) |
| 10 | corpus parsing-discrepancy (trích WAFFLED) | Long | ✅ 25/10: 3 ben + 3 mal; CRS chặn hết chunked/GET-body/CT-policy ở tầng transport (920640/920170/920420) — chưa đạt case "true bypass" (kết quả phủ định có giá trị) |
| 11 | gộp kết quả, TPR/FPR/FNR, precision/recall/F1, threshold sweep, latency, bar chart, rule ID hotlist | Huỳnh | 🔶 sơ bộ: matrix PL1–3 + per-technique tables + 4 SVG + bảng CRS/ML/hybrid (26/10, ĐVH); còn precision/recall per-technique + rule hotlist + external holdout/tải lặp |
| 12 | PL1→PL3 hardening + exception hẹp + re-test regression; report + slide có số liệu | cả nhóm | deliverables cuối kỳ |

Lưu ý khi biên soạn khuyến nghị: với từng bypass, nêu **cấu hình PL + exception
hẹp** đề xuất và chỉ ra **risk trade-off** thay vì khái quát "tăng PL cho an toàn"
— bằng chứng thực nghiệm cho thấy tăng PL tăng FPR (PL3); exception phải hẹp
theo param/endpoint và phải dựa trên evidence từng rule match.

---

## PHẦN 7 — SẢN PHẨM DỰ KIẾN (Expected Deliverables — slide cuối)

1. Working WAF Lab (✅ đã có)
2. Bypass Test Suite 4 kỹ thuật (✅ 26 case, schema khớp `docs/interfaces.md` + extension `transport`/`control`)
3. Automated testing (✅ `scripts/run_experiment.py`: direct control oracle, audit correlation, outcome classifier, evidence JSON/CSV)
4. Experimental dataset (raw → processed → evaluated) (⏳ mức DPO)
5. Kết quả định lượng: Detection/Bypass/FPR/FNR/Precision/Recall/F1 (✅ matrix PL1–3 + ML n=312 + enforcement; ⏳ external holdout)
6. Visualization CRS vs ML (✅ `results/graphs/bypass-decisions-by-pl.svg` + `bypass-fpr-by-technique.svg`)
7. Khuyến nghị cấu hình CRS theo PL + exception (🔶 sơ bộ — khuyến nghị ưu tiên
   PL1: FPR 9.1%, block 13/15 = 86.7%; **SQL-family detection 11/15 = 73.3% ổn
   định PL1→PL3**; PL3 block 100% nhưng FPR 72.7% — hướng khuyến nghị: PL1 +
   exception hẹp theo evidence; KHÔNG dùng số 86.7% làm "SQL-family recall")
8. Report + Presentation (⏳ chuẩn giữa kỳ theo format của môn)
