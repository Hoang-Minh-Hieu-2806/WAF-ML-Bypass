# T03 — Giáo án báo cáo giữa kỳ

> **Đề tài:** T03 — WAF học máy và kỹ thuật né tránh: tái lập tấn công đối kháng
> **Chương:** C4 (WAF bypass) · C5 — **Độ khó:** ★★★
> **Nhóm 5 thành viên:** Hoàng Minh Hiếu, Châu Gia Huy, Đặng Văn Hoàng, Lê Đình Long, Huỳnh Như Hoàng
> **Số slide đề xuất:** 14 — **Thời lượng:** 10–12 phút trình bày + demo 5 phút + QA

---

## PHẦN 1 — TÓM TẮT Ý TƯỞNG (slide 1–3, ~2 phút)

### 1.1. Đặt vấn đề

WAF là lớp phòng thủ lớp 7 phổ biến nhất. Có hai hướng tiếp cận:

- **Signature-based** (ModSecurity + OWASP CRS): khớp pattern/mã hóa đã biết.
- **ML-based**: học từ corpus labeled, phân loại request thành malicious/benign.

Cả hai đều có thể bị **vượt qua (bypass)** bằng phép biến đổi payload mà **WAF và ứng
dụng diễn giải khác nhau**. Điểm mấu chốt: payload chỉ là chuỗi byte; "ý nghĩa" của
nó là một **hàm của parser** đọc nó. Khi `WAF parser ≠ App parser`, cái WAF nhìn thấy
không phải là cái ứng dụng thực thi — đây là cơ chế gốc của bypass (cốt lõi của
nghiên cứu WAFFLED, ACSAC 2025; +10% phần chấm nếu nhóm nắm được và chứng minh được).

### 1.2. Ý tưởng đồ án

Dựng một **lab local 4 service** (Docker): Web App Flask cố tình vulnerable
(Flask + PyMySQL + MySQL 8.4) → WAF signature (ModSecurity v3 + CRS 4.30) →
và một WAF ML (TF-IDF + Logistic Regression/SVM) chạy song song. Sau đó:

1. Chạy bộ **baseline SQLi/benign** để đo hiệu suất gốc của từng WAF và False
   Positive theo Paranoia Level 1→2→3;
2. Áp **4 nhóm kỹ thuật né tránh** trong giáo trình C4 — HPP/Fragmentation,
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
| T05–06: ML-WAF pipeline & model | ✅ **Huấn luyện xong 25/10**: dataset 312 mẫu tự sinh + TF-IDF/LogReg, `model_version lr-tfidf-1.0` chạy thật trong container; còn review nhóm + mở rộng corpus | `waf-ml/train.py`, `results/tables/ml-v0-summary.md`, `waf-ml/app.py` |
| T07–08: HPP & Double-Encoding | ⏳ Chưa bắt đầu — schema test-case đã chốt 19/10 | `dataset/bypass/hpp|double-encoding/` đang trống |
| T09: Case Variation + SQL Comment | ⏳ Chưa bắt đầu | `dataset/bypass/case-comment/` trống |
| T10: Parsing Discrepancy | ⏳ Chưa bắt đầu — đã chọn hướng trích WAFFLED | `dataset/bypass/parsing-discrepancy/` trống |
| T11: Tổng hợp & phân tích | ⏳ Chưa — runner chưa implement nhưng contract output đã chốt | `scripts/README.md` |
| T12: Hardening & báo cáo | 🔶 Sơ bộ — phân tích FP PL2/PL3 đã có | mục FP trong `report/waf-crs-baseline.md` |

**Ước tính tổng tiến độ: ~40% kế hoạch 12 tuần — nhỉnh hơn pha giữa kỳ một nhịp.**
Kết quả thực nghiệm đã có (CRS trên backend thật): PL1 chặn 100% SQLi smoke
(6 case), 0% true bypass, FPR 0%; PL2 giữ nguyên; PL3 FPR 33% (rule `932350`
chặn nhầm tham số tên `id`). Song song đó, lab SQLite 13 case cho: PL1 100%/0% FPR,
PL3 37.5% FPR (942131, 932350, 920272 — FP UTF-8 tiếng Việt). Run PL mới
`20261025T172523Z-cecdfdeb` (26/10) tái lập đúng 3 số dòng trên sau khi ML v0
đã tích hợp (bảng: `results/tables/pl-summary-20261025.md`).

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
5. **ML scoring API — model học máy thật (25/10)**: `POST /score {"text"} →
   {"label","score","model_version"}` giờ trả nhãn từ **TF-IDF + LogisticRegression
   Euclidean `lr-tfidf-1.0`** train ngay trong container (GroupKFold leak-safe theo
   family: F1 90.8%/FPR 1.7%); regex stub chỉ còn fallback nếu image thiếu model.
6. **Schema test-case JSON chuẩn hóa** (điều kiện để biểu diễn HPP): `params`/`form` là
   **danh sách cặp có thứ tự**, giữ nguyên duplicate key — yêu cầu bắt buộc để
   biểu diễn HPP/parsing discrepancy (JSON object không được).
7. **Pipeline automation (dự kiến)**: `scripts/run_experiment.py` gửi payload →
   thu CRS decision + ML decision + app behavior cùng run-ID → CSV/JSON.
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
               └──────────────┘   waf-ml :8082 (FastAPI) — scoring engine
                                  POST /score {text} → {label,score,model_version}
```

- Mạng Docker bridge `waf-lab-webnet`; **chỉ HTTP ports bind loopback**, DB
  không publish; request source luôn là machine của nhóm.
- Log song song cùng correlation ID: audit WAF ↔ app evidence JSONL
  (`raw_target`, `parsed_pairs`, SQL, `row_ids`, `reference_row_ids`,
  `semantic_effect`, `http_status`).

### 4.2. Lộ đường xử lý ML (đang chờ nhóm review — slide 9)

Đề xuất trong `docs/architecture.md`: nhóm ưu tiên **proxy nhỏ trong
`waf-ml`** — thêm listener nội bộ, gọi model, `allow → forward web-app:5000 /
block → 403`; giữ nguyên `/score`. Phương án B là Nginx `auth_request` gateway.
Chốt trước tuần 07 để đo được "ML bypass rate" end-to-end, giữ contract.

### 4.3. Phân công theo module

| Thành viên | Module | Hiện trạng |
|---|---|---|
| Hiếu | docker-compose, Dockerfiles, DB init, docs | ✅ xong, hợp khối |
| Huy | ModSecurity + CRS (PL1–3, audit) | ✅ baseline + evidence xong |
| Đặng Văn Hoàng | waf-ml (dataset, TF-IDF+LR/SVM, API) | ✅ lr-tfidf-1.0 train xong 25/10 (F1 90.8%, FPR 1.7%); còn review nhóm + mở rộng corpus |
| Long | test-case 4 kỹ thuật bypass | ⏳ schema chốt; payload tuần 07+ |
| Huỳnh Như Hoàng | run_experiment.py + metrics + chart | ⏳ contract chốt; implement tuần 07+ |

---

## PHẦN 5 — CÁC KỊCH BẢN DEMO (slide 10–14)

> Chia 2 loại: **Demo sống** trên lab đã dựng (A–D) và **Demo bằng slide/
> bộ test-case** cho phần chưa làm (E, ý tưởng kịch bản sau giữa kỳ).

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
echo '{"text":"màn hình laptop 450"}' | ...   # → {"label":"benign","score":0.07}

# Boundary case — ví dụ cộng thêm về threshold (0.5):
#   "admin' -- #" → {"label":"malicious","score":0.5057}
#   (score sát ngưỡng — câu chuyện về trade-off threshold của classifier)
```

Kể câu chuyện (3 nhịp, 45 giây):
1. *"Model TF-IDF + LogReg được train trong container bằng sklearn pin sẵn,
   dataset tự sinh 312 mẫu, GroupKFold theo family nên mutation 'anh em' không
   được pha trộn giữa train/test"* — F1 90.8%, 20 miss do corpus nhỏ.
2. *"Per-family cho thấy ML yếu ở stacked (40%) / boolean (56%)"* — cơ hội
   cho tuần 07: corpus công khai (Kaggle SQLi 40k) + mutation WAF-A-MoLE.
3. Bảng/chart phục vụ: `results/tables/ml-v0-summary.md`
   + `results/graphs/waf-ml-family-detection.svg` + `results/graphs/pl-fpr-detection.svg`.

### Demo E — CORPUS 4 kỹ thuật bypass (kịch bản sau giữa kỳ — slide)

Bộ test-case dự kiến cho `dataset/bypass/<technique>/*.json` (Long sở hữu):

| Kỹ thuật | Payload mẫu | Cơ chế gốc (chiều WAF ≠ App) | Kỳ vọng đo lường |
|---|---|---|---|
| **HPP** | `/product?id=1&id=1 OR 1=1` | WAF duyệt từng occurrence của `ARGS:id`; Flask `request.args.get()` chỉ lấy **giá trị đầu tiên**; PHP và nhiều parser khác tổng hợp khác (join/last-value) | Bypass chỉ xảy ra nếu chính sách pha trộn giá trị của WAF khác App; đo trên chính parser của stack này |
| **Double Encoding** | `/search?q=%2527%2520OR%25201%253D1` (×2 decode → `' OR 1=1`) | WAF lưu ARGS sau **1 lượt decode**; CRS thêm transform `t:urlDecodeUni` theo từng rule nên nhiều payload double-encoded vẫn bị bắt — cần đo chính là điều này; App chỉ "thấy" `'` nếu code chủ động decode lần 2 (`unquote(unquote())`) | Chỉ tính bypass khi direct control có semantic effect; "không bypass" trên stack này cũng là một phát hiện (kết quả phủ định có giá trị) |
| **Case + Comment** | `-1 UnIoN/**/sElEcT/**/id,usER/**/FrOm/**/users--` | libinjection token hóa **không phân biệt hoa-thường** → case variation ít bypass; comment `/**/` che khoảng trắng phá tokenization (`1/**/OR/**/1=1`) — chính kỹ thuật mutation mà WAF-A-MoLE dùng | Đo % case rule `942xxx` vẫn bắt; so với mutation-space của WAF-A-MoLE |
| **Parsing Discrepancy** | Request với `Transfer-Encoding: chunked` + trailer header; duplicate-key form | WAF hợp nhất request theo một version RFC, App theo version khác → payload nằm ở vùng WAF không quan sát được (WAFFLED) | Demo 1 case đủ tiêu chí true bypass: audit không thấy attack, app thực thi SQLi |

Quy tắc bảo toàn kết quả: mỗi case luôn chạy 2 đường (direct + qua WAF) và
phải có `semantic_effect=true` ở direct control trước — không chấp nhận
"bypass" chỉ vì `HTTP 200`.

**Cập nhật 25/10 (sau giữa kỳ):** corpus 26 case đã *có thật* và chạy được —
`scripts/run_experiment.py`, evidence `results/raw/experiments/20261025T182650Z-4e5c2027/`
+ bảng `results/tables/bypass-matrix-20261025.md`. Kết quả PL1–3 (26 case × 3):
bypass thật 0/15 mọi PL; CRS block 13/15 ở PL1–2 và 15/15 ở PL3; nhưng FPR
benign 9.1% → 9.1% → **72.7%** (PL3 over-block bằng rule protocol 920230/920272/921180
chứ không phải SQL-family); 2 case DE `pass_without_effect` (CRS decode 1 lượt —
kết quả phủ định có giá trị đúng như bảng trên dự đoán).

### Q&A dự phòng (chuẩn bị trước)

- *"Vì sao CRS bắt được SQLi này — là khớp chuỗi không?"* → Không: `942100` là libinjection (SQL tokenization), `949110` là ngưỡng anomaly tổng hợp.
- *"Request qua WAF không để lộ gì?"* → DB không publish port, HTTP chỉ bind `127.0.0.1`, seed user giả trong lab, không có dữ liệu thật.
- *"Có dùng WAF-A-MoLE / sqlmap không?"* → Có, chỉ nhắm mục tiêu lab do nhóm kiểm soát (`scripts/requirements-attack.txt`, không cài vào image compose).
- *"PL3 FPR BEN-PRODUCT là chuyện gì?"* → Rule `932350` match **tên tham số** `id` (trùng tên lệnh Unix `id`), không nâng giá trị `1`. FPR 33% → hardening cần exception hẹp theo endpoint/param, có evidence.

---

## PHẦN 6 — CÔNG VIỆC TIẾP THEO (KẾ CHẾ VỀ SAU GIỮA KỲ)

| Tuần | Công việc | Owner | Đầu ra |
|---|---|---|---|
| 05–06 (✅ 25/10) | Dataset SQLi/benign → TF-IDF + LR → thay stub `/score` (giữ nguyên contract) — `lr-tfidf-1.0` F1 90.8%/FPR 1.7%, train-in-container | Đặng Văn Hoàng | `waf-ml/train.py` + `results/tables/ml-v0-summary.md` |
| 05–06 (đang) | Review cơ chế ML enforcement proxy (option 1) | Hiếu + ĐVH + Huỳnh | chốt trước tuần 07, cập nhật `docker-compose.yml` với proxy scoring |
| 07–08 | `run_experiment.py` + corpus HPP + double-encoding; chạy trên CRS **và** ML | Long + Huỳnh | ✅ 25/10: runner + corpus 26 case + matrix PL1–3 (bypass 0, FPR PL3 72.7%) |
| 09 | corpus case/comment | Long | ✅ 25/10: 3 ben + 5 mal (cc-mal-004 fixed payload → effect true) |
| 10 | corpus parsing-discrepancy (trích WAFFLED) | Long | ✅ 25/10: 3 ben + 3 mal; CRS chặn hết chunked/GET-body/CT-policy ở tầng transport (920640/920170/920420) — chưa đạt case "true bypass" (kết quả phủ định có giá trị) |
| 11 | gộp kết quả, TPR/FPR/FNR, precision/recall/F1, bar chart, rule ID hotlist | Huỳnh | bảng tổng kết bằng kỹ thuật |
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
5. Kết quả định lượng: Detection/Bypass/FPR/FNR/Precision/Recall/F1 (✅ mức matrix PL1–3 + ML n=312; ⏳ đầy đủ precision/recall per-technique)
6. Visualization CRS vs ML (✅ `results/graphs/bypass-decisions-by-pl.svg` + `bypass-fpr-by-technique.svg`)
7. Khuyến nghị cấu hình CRS theo PL + exception (🔶 sơ bộ — matrix ưu tiên PL1: FPR 9.1%, SQL-family recall 86.7% nhất quán PL1→PL3)
8. Report + Presentation (⏳ chuẩn giữa kỳ theo format của môn)
