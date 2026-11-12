# Technical Design v3.1 — Mở rộng WAF SQLi → SQLi + XSS

> **Trạng thái tài liệu:** THIẾT KẾ + AUDIT. Chưa triển khai. Chưa merge/commit/restore.
> **v3.1** = v3 + 9 chỉnh sửa bắt buộc từ review chủ dự án (X5 accounting, ML
> enforcement policy, browser verification tách app-control/WAF-path, ML
> acceptance, timeline không vòng lặp, endpoint an toàn, schema làm rõ,
> StratifiedGroupKFold checks, requirements-attack.txt nguyên văn). Đối chiếu
> đầy đủ ở §21. Chỉ file này được sửa; không file dự án nào khác bị đụng.
> Nền tảng: Technical Design v2 + feedback chủ dự án (Vấn đề A–F).
>
> **Quy ước phân loại kiến thức trong tài liệu:**
> - **[AUDIT]** — đã kiểm chứng trực tiếp trên repo (git/lệnh read-only/đọc file).
> - **[DESIGN]** — đề xuất thiết kế, chưa được thực nghiệm.
> - **[UNVERIFIED]** — giả định/chưa xác minh, được liệt kê trong §19.

---

## 1. Executive Summary

v3.1 mở rộng đồ án từ SQLi sang **SQLi + XSS** trên cùng lab 4 service. So với v2,
v3 giữ nguyên 5 thiết kế cốt lõi và **sửa thêm 5 điểm mâu thuẫn mà v3 còn sót**:

1. **Oracle 2 tầng có tính hợp lệ per-case (giải quyết Vấn đề A):** HTTP oracle đo
   `reflected` theo từng case; browser oracle (Playwright) tách 2 chế độ
   **app-control** và **WAF-path** (v3.1 — xem §7); case chưa verify browser mang
   `execution_status = execution_unverified` và **không bao giờ** được kết luận
   `true_bypass_xss`.
2. **Schema v2 thống nhất (Vấn đề B):** tách `vuln` / `technique` / `family` /
   `expected_waf_outcome` / `expected_app_effect` / `control`. `blocked` là kết
   quả WAF, **không** bao giờ nằm trong `expected_app_effect` (v3.1 làm rõ thêm:
   `expected_app_effect` mô tả hiệu ứng khi request đến **trực tiếp app**, độc
   lập WAF — §5.2). Tương thích ngược 26 case SQLi v1 — không yêu cầu chuyển đổi.
3. **Tách bạch Detection / Blocking / Application Effect (Vấn đề C):** cấu trúc
   actual-result riêng, rule family phân loại từ **rule ID thực tế** trong audit
   log, không giả định mọi XSS đều do 941xxx.
4. **ML 3 lớp `lr-tfidf-3cls-1.1` (Vấn đề D):** sửa lỗi naming v2
   (`lr-tfidf-2cls-1.1` sai — model có 3 lớp). Giữ artifact v1.0, không ghi đè;
   StratifiedGroupKFold theo family (scikit-learn **1.7.1** — [AUDIT]
   `waf-ml/requirements.txt:6` — hỗ trợ API này). v3.1 sửa thêm: enforcement
   policy = **tổng xác suất attack**, không phải argmax-label (§10); acceptance
   criteria không so macro-F1 với binary-F1 kiểu −0.05 (§9.5).
5. **X5 run matrix chính xác (Vấn đề F):** 2 run-ID (RUN-A: direct + CRS-only +
   ML-only; RUN-B: direct + Hybrid), mỗi run PL1–3, corpus 36 case
   (26 SQLi + 10 XSS). v3.1 đếm đúng từng loại lượt: **324 WAF case executions,
   216 direct-control requests, ≈540 HTTP requests** — khác nghĩa, không gộp
   chung (§12.1).

Không thay đổi phạm vi SQLi hiện có; toàn bộ số liệu baseline đã xác minh được giữ.

---

## 2. Mục tiêu và phạm vi mở rộng

**Mục tiêu:** mở rộng evaluation surface từ 1 loại lỗ hổng (SQLi) sang 2 (SQLi + XSS)
trên cùng corpus technique (HPP / Double-encoding / Case+comment /
Parsing-discrepancy), nhằm:
- trả lời góp ý review #5A/#5B về tỷ lệ bypass per-technique;
- chứng minh oracle phân biệt bypass thật vs pass-through trên 2 vuln;
- đo CRS vs ML vs Hybrid per-vuln × per-technique.

**Trong phạm vi:** lab local 4 service; endpoint XSS chỉ reflect trong lab nội bộ;
Playwright chạy trên host, không vào image compose (quy tắc
`docs/interfaces.md §4` — tool tấn công ngoài compose).

**Ngoài phạm vi:** stored XSS (không có bảng lưu user-content trong schema DB hiện
tại), DOM XSS (payload không qua HTTP), CSRF, SSRF. Ghi nhận trong Future Work.

---

## 3. Current Architecture và Delta Architecture

### 3.1 Current (đã chạy thật — [AUDIT] từ code + evidence)

```text
Runner :8080 direct ─► web-app (Flask+PyMySQL) ─► db (MySQL 8.4, nội bộ webnet)
Runner :8081 ─► waf-crs (nginx + ModSec 3.0.17 + CRS 4.30, PL1–3) ─► web-app
Runner :8082 ─► waf-ml (FastAPI proxy: score → 403 | forward raw) ─► web-app
```

Oracle hiện tại: SQLi-only (`semantic_effect` = row-ID ngoài tập tham chiếu bind
param trên cùng connection). Evidence JSONL per-case theo `X-Lab-Case-ID`.

### 3.2 Delta Architecture [DESIGN]

```text
                         ┌── /comment          (VULN:  text/html, reflect RAW input)
Runner ─► web-app ───────┤
                         └── /comment-escaped  (CONTROL: cùng code path, html-escape)

HTTP oracle (per-case, trong runner):  xss_reflected = reflect(/comment) && !reflect(/comment-escaped)
Browser oracle (per-case targeted):    Playwright headless → DOM marker / document.title
                                       → execution_status ∈ {executed, not_executed,
                                         execution_unverified}
```

- **Không thêm service, không đổi network, không đổi DB.**
- CRS: không thêm rule — 941xxx có sẵn trong image `owasp/modsecurity-crs`;
  `MODSEC_RESP_BODY_ACCESS: Off` giữ nguyên (đúng cho reflected XSS — [AUDIT]
  `docker-compose.yml:79`).
- ML proxy: path-agnostic sẵn (catch-all `/{path}` — [AUDIT] `waf-ml/app.py:147`);
  `/comment*` tự đi qua scoring, không sửa proxy routing.
- **Sửa code chỉ 2 service:** `web-app` (2 endpoint + oracle), `waf-ml` (3-class
  label + enforcement policy). Cả hai rebuild image, không đụng `db`.

---

## 4. Phase 0 Git Audit (kết quả giữ nguyên từ v2, đã [AUDIT])

### 4.1 Số kiện đã kiểm chứng

| Mục | Kết quả [AUDIT] |
|---|---|
| Commit `12e597b` (feature/crs) | 27/10/2026; 15 files +656/−115; fix audit permissions (`docker/waf-crs/init-audit.sh`), fix DB password parsing (`web-app/app.py` — `DB_PASSWORD` env), thêm `waf-crs/test_integrated_smoke.py` (108 dòng), `docs/modsecurity-walkthrough.md`, `report/crs-p2-fixes.md` |
| Divergence | merge-base `dev` ↔ `feature/crs` = `4ec4c0c`; `dev` đi trước 13 commits; `feature/crs` có đúng 1 commit trên base |
| Conflict (merge-tree read-only) | 5 files changed-in-both: `.env.example`, `README.md`, `docker-compose.yml`, `docs/architecture.md`, `docs/quickstart-lab.md` — dự kiến conflict nhỏ, resolve theo hunk. `web-app/app.py`, `waf-crs/run_integrated_smoke.py`: chỉ dev đổi → merge sạch |
| `scripts/requirements-attack.txt` (working tree) | Nội dung gốc (commit `1dcf7d0` — nguyên văn dưới đây, lấy từ `git diff` read-only) bị **thay toàn bộ** bằng 5 dòng cheat-sheet runner (trùng lặp `scripts/README.md`). Đánh giá: overwrite ngoài ý muốn |

**Nội dung gốc nguyên văn (v3.1 — đã lưu trong tài liệu này, không còn là tuyên bố
chưa xác minh; nguồn: output `git diff scripts/requirements-attack.txt`, các dòng
`-`, tức nội dung HEAD):**

```text
# T03 — Tool tấn công cho lab local (KHÔNG cài trong image compose, xem docs/interfaces.md §4)
# Cài riêng trên máy: python -m pip install -r scripts/requirements-attack.txt
# Chỉ dùng với target trong lab do nhóm kiểm soát (xem SECURITY.md).
sqlmap>=1.8
# WAF-A-MoLE: cài từ repo GitHub chính thức của nhóm tác giả
# (xem mục Tài liệu tham khảo WAF-A-MoLE trong README.md).
```

Ghi chú phạm vi xác minh: nguyên văn trên là nội dung **HEAD** (diff modified-vs-index
đã chạy [AUDIT]); chưa checkout `1dcf7d0` để đối chiếu nguyên trạng (vi phạm ràng
buộc) — diff 6 dòng `@@ -1,6 +1,6 @@` phủ toàn bộ file nên đây là nội dung HEAD
đầy đủ. File đang modified trong working tree **không bị đụng** trong toàn bộ
nhiệm vụ v3.1.

### 4.2 Kế hoạch Phase 0 (v3 — theo ràng buộc chủ dự án, chưa thực hiện)

```text
B0.1 Lưu diff requirements-attack.txt vào design doc (§4.1) + giữ working tree
     nguyên vẹn. KHÔNG restore tự động — chờ chủ dự án xác nhận là overwrite
     ngoài ý muốn (nội dung gốc đã được sao lưu nguyên vẹn trong tài liệu này).
B0.2 Trên dev (trước merge): chạy R1, R2, R3, R4-minimal (baseline PASS/FAIL
     snapshot, lưu output vào design-report riêng).
B0.3 Tạo worktree tích hợp thử: git worktree add ../waf-t3-merge dev
     → merge feature/crs trong worktree (KHÔNG đụng working tree hiện tại,
       KHÔNG đổi dev cho đến khi test pass).
B0.4 Resolve 5 conflict theo hunk (ops-fix của 12e597b + ML của dev).
B0.5 Trong worktree: chạy R1, R2, R9 (test_integrated_smoke.py — file CHỈ tồn
     tại sau merge, do 12e597b tạo) + smoke docker compose up trong worktree.
B0.6 PASS → merge commit đưa vào dev (fast, một lần). FAIL → báo cáo, không merge.
B0.7 dev → main: CHỈ sau khi X1–X5 hoàn tất và toàn bộ regression pass (§14).
```

⚠️ Lưu ý thứ tự: `12e597b` sửa `web-app/app.py`; X1 cũng sửa `web-app/app.py` →
merge feature/crs **phải xong trước** khi X1 bắt đầu để tránh conflict chồng lấn.

---

## 5. Test Case Schema v2 (giải quyết Vấn đề B)

### 5.1 Phân biệt technique vs family

| Khái niệm | Định nghĩa | Ví dụ |
|---|---|---|
| **technique** | Cách biến đổi/tạo payload trên wire (4 nhóm C4, dùng chung cho SQLi & XSS) | `hpp`, `double-encoding`, `case-comment`, `parsing-discrepancy` |
| **family** | Nhóm mẫu cùng **cơ chế payload**, dùng cho GroupKFold ML + đánh giá tổng quát hóa | `union`, `tautology-n` (SQLi); `xss.tag`, `xss.event` (XSS); `benign.html` |

Cùng một technique có thể chứa nhiều family: case `xss-cc-mal-001` (case+comment
biến đổi `<ScRiPt/**>`) có technique=`case-comment`, family=`xss.tag` (cơ chế là
tag injection), case `xss-cc-mal-002` (`<ImG onerror=…>`) cũng technique=
`case-comment` nhưng family=`xss.event`. Đây là lý do schema phải có cả hai.

### 5.2 Schema v2 (contract cho runner)

```jsonc
{
  "id": "xss-cc-mal-001",              // duy nhất toàn corpus
  "vuln": "sqli | xss",               // loại lỗ hổng
  "technique": "hpp | double-encoding | case-comment | parsing-discrepancy",
  "family": "xss.tag",                // cơ chế payload — dùng cho GroupKFold
  "label": "benign | malicious",
  "request": {                        // thông tin HTTP — cấu trúc duy nhất
    "method": "GET | POST",
    "path": "/search | /product | /login | /comment | /comment-escaped",
    "params": [["k","v"], ...],       // danh sách cặp có thứ tự (giữ duplicate)
    "form":   [["k","v"], ...],
    "headers": {},
    "transport": null                 // null | "chunked"
  },
  "expected_waf_outcome": "blocked | allowed",        // CHỈ kết quả WAF
  "expected_app_effect": "executed | not_executed | none",  // CHỈ hiệu ứng app
  "control": {                        // optional — endpoint/request đối chứng
    "endpoint": "/comment-escaped",
    "must_not": ["reflect", "execute"]
  },
  "note": "giả thuyết cơ chế WAF≠App"
}
```

**Quy tắc bắt buộc:**
- `blocked` **không được xuất hiện** trong `expected_app_effect` — đó là kết quả
  WAF (`expected_waf_outcome`), không phải hiệu ứng ứng dụng.
- `expected_app_effect` chỉ 3 giá trị; benign luôn `none`.
- **v3.1 — ngữ nghĩa hai trục kỳ vọng độc lập:** `expected_app_effect` mô tả
  hiệu ứng ứng dụng **khi request đến trực tiếp app (direct control)**, độc lập
  với quyết định WAF. Một case có thể `expected_waf_outcome: "blocked"` đồng thời
  `expected_app_effect: "executed"` (ví dụ ①) — hai kỳ vọng không suy ra nhau.
- **Cách so expected vs actual:**
  - *Direct control:* actual app effect (từ app.jsonl) phải khớp
    `expected_app_effect` → vi phạm = `control_invalid`, case bị loại khỏi mẫu
    số metrics (giữ nguyên cơ chế hiện có [AUDIT `run_experiment.py:210-222`]).
  - *WAF path:* actual app effect (trên request được phép qua) được so với
    direct-control effect của cùng case — khác nhau ⇒ phân loại
    `pass_without_effect` / `true_bypass` (WAF cắt hiệu ứng) hoặc khớp ⇒ case
    được đo tiếp detection/blocking. Không dùng `expected_waf_outcome` để phân
    loại outcome thực tế — nó chỉ là kỳ vọng tài liệu.
- `params`/`form` là danh sách cặp có thứ tự (giữ quy tắc v1 — HPP cần).

### 5.3 Ví dụ contract (4 mẫu)

**① SQLi theo schema mới (case cũ được viết lại minh họa — KHÔNG bắt buộc chuyển đổi):**

```json
{
  "id": "hpp-mal-001",
  "vuln": "sqli",
  "technique": "hpp",
  "family": "tautology-n",
  "label": "malicious",
  "request": {"method": "GET", "path": "/product",
              "params": [["id","1 OR 1=1"],["id","5"]],
              "form": [], "headers": {}, "transport": null},
  "expected_waf_outcome": "blocked",
  "expected_app_effect": "executed",
  "control": null,
  "note": "Flask first-value-wins thực thi occurrence đầu; CRS thấy cả 2 values"
}
```

**② XSS malicious:**

```json
{
  "id": "xss-cc-mal-001",
  "vuln": "xss",
  "technique": "case-comment",
  "family": "xss.tag",
  "label": "malicious",
  "request": {"method": "GET", "path": "/comment",
              "params": [["text","<ScRiPt/**>document.title='T3-XSS-OK'</script>"]],
              "form": [], "headers": {}, "transport": null},
  "expected_waf_outcome": "allowed",
  "expected_app_effect": "executed",
  "control": {"endpoint": "/comment-escaped", "must_not": ["reflect","execute"]},
  "note": "case+comment đổi ranh giới token; đo CRS 941xxx có thấy sau decode không"
}
```

**③ Benign HTML (FP check):**

```json
{
  "id": "xss-de-ben-001",
  "vuln": "xss",
  "technique": "double-encoding",
  "family": "benign.html",
  "label": "benign",
  "request": {"method": "GET", "path": "/comment",
              "params": [["text","%3Csup%3Eregs%3C%2Fsup%3E ghi chú 1.3"]],
              "form": [], "headers": {}, "transport": null},
  "expected_waf_outcome": "allowed",
  "expected_app_effect": "none",
  "control": null,
  "note": "snippet HTML vô hại — đo FPR CRS/ML với ký tự <, tag thường"
}
```

**④ Case có control endpoint:**

```json
{
  "id": "xss-hpp-ben-002",
  "vuln": "xss",
  "technique": "hpp",
  "family": "benign.lt",
  "label": "benign",
  "request": {"method": "GET", "path": "/comment",
              "params": [["text","khoảng giá a < b < c"],["text","ghi chú 2"]],
              "form": [], "headers": {}, "transport": null},
  "expected_waf_outcome": "allowed",
  "expected_app_effect": "none",
  "control": {"endpoint": "/comment-escaped", "must_not": ["reflect","execute"]},
  "note": "dup param benign; đồng thời là FP check cho so sánh a < b"
}
```

### 5.4 Tương thích ngược 26 case v1

- Runner chấp nhận **cả** v1 (flat: `method/path/params/form/expected_app`) lẫn
  v2 (bọc `request` + `expected_effect`/`expected_waf_outcome`).
- Map: `expected_app: "executed" → expected_app_effect:"executed"`,
  `"blocked" → expected_waf_outcome:"blocked", expected_app_effect:"none"`.
- `vuln` mặc định `"sqli"`, `family` v1 mặc định suy từ prefix case-id (tài liệu
  hóa trong README corpus); **không yêu cầu sửa/convert 26 file cũ**.
- Số case XSS chính thức: mục tiêu **10 (4 benign + 6 malicious)** → corpus 36.
  Con số là mục tiêu thiết kế; chốt tại implementation review (không tự tuyên bố
  đã tạo dataset).

### 5.5 Phân bổ family XSS (taxonomy đề xuất)

| family | mechanism | ben | mal |
|---|---|---|---|
| `xss.tag` | tag injection (script, img, svg) | — | 2 |
| `xss.event` | event handler (onerror/onload) | — | 1 |
| `xss.encoding` | double-encoded / percent-encoded payload | 1 | 1 |
| `xss.case-comment` | case + comment mutation trên tag/attr | — | 2 |
| `xss.hpp` | HPP duplicate param trên context XSS | — | — (thuộc case trên) |
| `benign.html` | HTML vô hại (sup, markdown, code fence) | 2 | — |
| `benign.lt` | ký tự `<`/`>` trong văn bản, so sánh | 2 | — |

(10 case phân bổ cụ thể chốt ở implementation review; bảng trên là budget thiết kế.)

---

## 6. XSS Endpoint và Application Control (giải quyết Vấn đề E)

### 6.1 Hai endpoint

| Endpoint | Hành vi | Vai trò |
|---|---|---|
| `GET /comment?text=` | trả `text/html` từ **template HTML cố định** do code định nghĩa, chèn giá trị `text` vào vị trí sink **raw, không escape** (cố ý — nối chuỗi vào template string, KHÔNG dùng input làm template source) | Sink XSS cố ý — lab-only |
| `GET /comment-escaped?text=` | cùng template cố định, nhưng giá trị `text` được `html.escape()` trước khi chèn | Application control |

**Ràng buộc an toàn của endpoint (v3.1):**
- **Cấm** `render_template_string(user_text)` hoặc bất kỳ hình thức nào lấy input
  người dùng làm **template source** (mở đường SSTI thay vì chỉ XSS — sai đối
  tượng nghiên cứu). Input chỉ được chèn như **giá trị** vào template cố định:
  `f"<html><body><div class='note'>{raw}</div></body></html>"` cho endpoint vuln,
  và `{html.escape(raw)}` cho endpoint control.
- Endpoint chỉ serve trong **lab nội bộ**: Flask bind loopback bên trong compose
  network (`webnet`), port host bind `127.0.0.1` như các service hiện có [AUDIT
  `docker-compose.yml:50`]; **không triển khai public, không dữ liệu thật** —
  cùng cam kết Ethical & Safety Scope trong README.
- Cả hai: không secret, evidence JSONL thêm `vuln:"xss"`, `xss_reflected`,
  `rendered_snippet` (200 ký tự đầu) — schema SQLi cũ không đổi.

### 6.2 Hai phép kiểm thử tách bạch

**① Application control — kiểm chứng app, KHÔNG qua WAF:**
- Gọi trực tiếp Flask (unit test / direct HTTP tới :8080, bypass cả CRS lẫn ML).
- Kỳ vọng: `/comment` reflect raw (marker unescaped); `/comment-escaped` render
  `&lt;script&gt;` … **không** có `<script>` literal trong HTML.
- Browser check trên cả hai: executed=true chỉ được ở `/comment`.
- **Củng cố:** escaping hoạt động được chứng minh bởi **app itself**, không bao giờ
  bởi việc WAF chặn request.

**② WAF path — đo detection/blocking, không dùng làm bằng chứng app safety:**
- Cùng payload gửi qua :8081 (CRS) và :8082 (ML) → đo `detected`/`blocked`/
  `rule_ids`.
- **Củng cố:** "CRS chặn payload X" không chứng minh "app escape an toàn với X" —
  hai phép đo độc lập, báo cáo riêng.

### 6.3 Test cases chuẩn cho cả hai đường

| ID | Đường | Input | Expected |
|---|---|---|---|
| AC-1 | app control (direct) | `<script>document.title='AC1'</script>` tại /comment | reflect + executed (browser) |
| AC-2 | app control (direct) | cùng input tại /comment-escaped | `&lt;script&gt;` trong body; **not_executed** |
| AC-3 | app control (direct) | `%3Cscript%3E` (encoded 1 lượt) tại /comment | Flask/Werkzeug decode 1 lượt → reflect + executed |
| AC-4 | app control (direct) | `%253Cscript%253E` (encoded 2 lượt) tại /comment | Werkzeug decode 1 lượt → literal `%3Cscript%3E` → **not_executed** |
| WAF-1 | qua CRS | AC-1 payload | đo: blocked? detected 941xxx? — **kết quả thực nghiệm, không đặt trước** |
| WAF-2 | qua ML | AC-1 payload | đo: score/label 3-class, blocked? |
| WAF-3 | qua hybrid | AC-1 payload | đo: blocking_layer |

(AC-1..4 là đặc tả test cho `web-app/test_app.py`; kết quả WAF-1..3 là dữ liệu
thực nghiệm của X5, không phải kỳ vọng đặt sẵn.)

---

## 7. Oracle Design: HTTP + Browser (giải quyết Vấn đề A — v3.1 tách 2 chế độ verify)

### 7.1 Hai tầng oracle — tính hợp lệ per-case

**Tầng 1 — HTTP oracle (per-case, trong runner, nhanh):**
- `reflected` = response body `/comment` chứa payload (sau decode transport)
  unescaped **VÀ** response `/comment-escaped` cùng payload không chứa literal
  (đối chứng bắt buộc — chống false positive reflect từ khoá chữ trùng).
- Không dùng marker-containment làm bằng chứng duy nhất cho bypass — chỉ là tín
  hiệu HTTP tầng 1.

**Tầng 2 — Browser oracle (Playwright), 2 chế độ tách bạch (v3.1):**

| Chế độ | Truy cập qua | Mục đích | Kết luận được cho phép |
|---|---|---|---|
| **app-control verification** | Flask trực tiếp (`:8080`, không qua CRS/ML) | Chứng minh `/comment` thực thi JS và `/comment-escaped` **không** thực thi — tính chất của app | `executed`/`not_executed` **cho app-control evidence** (AC-1..4, R6). KHÔNG dùng để kết luận true bypass |
| **WAF-path verification** | Đúng endpoint WAF đã được đánh giá: CRS `:8081`, ML `:8082`, hoặc hybrid (chuỗi `:8081` với `CRS_BACKEND=ml`) | Chứng minh request được WAF cho phép **và** JS thực sự thực thi trong app qua đúng đường đó | `executed` cho **true_bypass_xss** — của đúng case, đúng configuration, đúng PL |

Quy tắc: kết quả browser của một case ở một chế độ **không suy rộng** cho chế độ
khác, và kết quả ở một PL/configuration không suy rộng cho PL/configuration khác.
Chỉ WAF-path verification của đúng bộ (case, config, PL) mới đủ điều kiện
`true_bypass_xss`.

### 7.2 Phạm vi browser verification

**App-control verification** (một lần sau X1, trước RUN-A/B — gate R6):
toàn bộ case XSS malicious + 2 control case (benign đại diện) — chạy trên
direct endpoint, xác nhận oracle app-side hợp lệ **trước** khi matrix chạy.

**WAF-path verification** (sau RUN-A/RUN-B — R7):
Browser oracle **bắt buộc** chạy cho:
1. Mọi case XSS malicious được WAF cho phép (candidate `true_bypass_xss`) —
   per (config, PL) mà nó được phép;
2. Mọi case bị nghi `pass_without_effect` (phân biệt không-executed vs chưa-verify);
3. Case chọn làm demo.

Tối ưu thời gian: **không** chạy browser cho case đã `blocked` (app không nhận
request — execution vô nghĩa) và có thể hoãn cho benign; mọi case chưa verify mang
`execution_status = "execution_unverified"`. Danh sách các (case, config, PL)
cần WAF-path verify được sinh **từ kết quả RUN-A/RUN-B** (pending list) — vì vậy
R7 nằm **sau** X5, không phải trước (v3 sai thứ tự này — đã sửa ở §15).

### 7.3 Định nghĩa trạng thái + outcome

| `execution_status` | Định nghĩa | Ý nghĩa metrics |
|---|---|---|
| `executed` | browser xác nhận JS chạy (DOM marker/title) — **trong chế độ tương ứng** | đủ điều kiện `true_bypass_xss` **chỉ nếu là WAF-path verification của đúng (case, config, PL)** |
| `not_executed` | browser chạy, không thấy tín hiệu | `pass_without_effect` (đã có bằng chứng kiểm) |
| `execution_unverified` | browser chưa chạy cho bộ (case, config, PL) này | **không được** tính `true_bypass_xss`; metrics đánh dấu pending |
| `blocked` | WAF chặn — không tới app | không áp dụng execution |
| `reflected` | (tín hiệu HTTP tầng 1) | điều kiện cần, không đủ |

**Định nghĩa `true_bypass_xss` per-case per-(config, PL) — v3.1:**

```text
true_bypass_xss(case, config, PL) =
    (label = malicious)
  ∧ (WAF decision = allowed tại config, PL này)   // CRS và/hoặc ML cho qua
  ∧ (rule_ids tại config, PL này không chứa XSS/SQLi family rule — detection=false)
  ∧ (reflected = true)                            // HTTP oracle, đúng run
  ∧ (execution_status = executed)                 // WAF-path verification đúng
                                                  //   case + config + PL
```

`execution_unverified` ⇒ true_bypass_xss = false + trạng thái pending; case đó
vào danh sách bắt buộc verify WAF-path browser trước khi chốt metrics.
App-control `executed` ở direct là **điều kiện nền** (oracle hợp lệ) nhưng
**không** thay thế WAF-path verification.

### 7.4 Browser evidence JSON (schema đề xuất — v3.1 bổ sung trường)

```jsonc
{
  "case_id": "xss-cc-mal-001",
  "verification_mode": "app_control | waf_path",   // MỚI v3.1
  "configuration": "crs_only | ml_only | hybrid",  // MỚI v3.1 — config đã đánh giá
  "paranoia_level": 1,                             // MỚI v3.1
  "endpoint": "/comment",                          // URL thực tế browser truy cập
  "test_timestamp": "2026-11-14T09:00:00Z",
  "http_status": 200,
  "reflected": true,
  "executed": true,
  "execution_signal": "dom_marker | title_change | dialog | none",
  "browser_error": null,
  "screenshot_path": "results/raw/browser/xss-cc-mal-001.png",
  "commit_hash": "<git rev-parse HEAD>",
  "corpus_sha256": "<sha256 của các cases.json>",
  "run_id": "<run-id tương ứng nếu là waf_path>"
}
```

Location: `results/raw/browser/<run-id>/…` (gitignore theo quy ước evidence raw).

---

## 8. Detection / Blocking / Application Effect (giải quyết Vấn đề C)

### 8.1 Ba khái niệm độc lập — actual result riêng

```jsonc
"actual": {
  "detected": false,          // WAF có rule match payload-family? (KHÔNG suy ra blocked)
  "blocked": true,            // request bị chặn? (từ HTTP status + evidence)
  "blocking_layer": "crs",    // crs | ml | null
  "rule_ids": ["941100", "949110"],   // ID THỰC TẾ từ audit JSON
  "rule_families": ["xss-rule", "anomaly-gate"],  // phân loại từ ID
  "app_effect": null,         // sqli: row-extra; xss: reflected+executed; benign: none
  "execution_status": "blocked"
}
```

**Quy tắc suy luận cấm:**
- `detected=true ⇏ blocked=true` (PL cho phép rule match mà không đủ anomaly score);
- `reflected ⇏ executed` (response chứa string ≠ JS chạy);
- `blocked=true ⇏ detected=true` (chặn bởi transport/protocol rule).

### 8.2 Phân loại rule ID từ audit log (không mặc định 941)

```text
rule_families map (áp cho ruleId THỰC TẾ trong audit):
  94xxx → libinjection/regex SQLi cụ thể: 942* → "sqli-rule"
  941*  → "xss-rule"
  920*/921* → "protocol-transport"
  932*  → "rce-rule"
  949110 → "anomaly-gate" (gate chặn, không tính detection)
  khác   → "other:<id>" (báo cáo nguyên trạng, không đoán)
```

Giữ nguyên cách tách đã dùng trong bypass-matrix 20261025: SQL-family vs
protocol đã được phân theo rule-id thực tế từng case [AUDIT
`results/tables/bypass-matrix-20261025.md:55-65`] — v3 áp cùng phương pháp cho
XSS, **không** giả định rule 941 bắt mọi case.

5 trạng thái phân biệt được yêu cầu:
`xss-rule` / `sqli-rule` / `protocol-transport` / `anomaly-gate(949110)` / `ml` —
mỗi case report `rule_families` + `blocking_layer`; ML blocking có evidence riêng
(`ml.jsonl` decision).

---

## 9. ML Multi-class Design (giải quyết Vấn đề D)

### 9.1 Naming — sửa lỗi v2

v2 ghi `lr-tfidf-2cls-1.1` — **sai** (model có 3 lớp). v3 chốt:
**`lr-tfidf-3cls-1.1`**. Lý do: convention hiện tại `lr-tfidf-1.0` =
`<model>-<version>`; thêm `3cls` thể hiện đúng số lớp, version tăng vì schema
output đổi (breaking cho consumer của `/score`). Không đổi tên ví dụ khác.

### 9.2 Dataset [DESIGN — số cuối chốt khi tạo]

- **Giữ nguyên 312 mẫu** (133 mal / 179 ben, 16 family) — [AUDIT]
  `waf-ml/build_dataset.py` + `results/tables/ml-v0-summary.md`.
- Thêm: XSS malicious (≈55–60 mẫu, 4 family theo §5.5 mở rộng cho ML) + benign
  HTML (≈25–35 mẫu: tag vô hại, `a < b`, markdown, dấu `<` trong tiếng Việt,
  attribute-like text). **Ước tính n≈390–410 — KHÔNG tuyên bố số cuối trước khi
  dataset được sinh + dedup kiểm.**
- Rủi ro mất cân bằng: benign vẫn đa số (≈55%). Mitigation: giữ macro-F1 làm
  metric chính + theo dõi per-class; cân nhắc `class_weight="balanced"` (đề xuất,
  so sánh với không-weight trong fold — quyết định theo số thực nghiệm, không đặt
  trước).

### 9.3 False-positive checks cho benign HTML

Bộ kiểm FP bắt buộc (chạy trên model final-fit + báo cáo trong metrics):
- ký tự `<`/`>` đơn lẻ trong văn bản thường, tiếng Việt;
- tag vô hại (`<sup>`, `<b>`, `<code>`), markdown (`**bold**`, `` `code` ``);
- attribute-like text (`class="a"`, `href=#` không tag đóng mở);
- snippet code (`if a < b: return c`).
Ghi nhận mỗi nhóm vào `metrics.json.fp_checks_html`.

### 9.4 Validation [DESIGN]

- **StratifiedGroupKFold(5, group=family)** — khả dụng: scikit-learn **1.7.1**
  pin trong `waf-ml/requirements.txt` [AUDIT]; API có từ sklearn 1.1+.
- **Kiểm tra tính hợp lệ fold (v3.1 — bắt buộc, chạy và báo cáo trong metrics):**
  1. *Family không chia đôi:* mỗi family chỉ nằm train **hoặc** validation
     trong mỗi fold (assert trong code; vi phạm = fail validation, không dùng số).
  2. *Đủ 3 lớp mỗi fold:* mỗi fold validation chứa cả benign/sqli/xss — check
     và báo cáo per-fold distribution.
  3. *Số family độc lập per class:* báo cáo số family riêng biệt của từng class
     (benign/sqli/xss) — class có <2 family độc lập là không đủ điều kiện cho
     fold-validate và phải được ghi nhận.
  4. *Nếu không tạo được 5 fold hợp lệ* (family quá nhỏ/leak): **báo cáo rõ** —
     thử giảm số fold (5→4→3) hoặc thiết kế lại family; KHÔNG tự động coi
     fallback GroupKFold là tương đương — nếu bắt buộc dùng GroupKFold thì phải
     đánh dấu rõ metrics đó là "GroupKFold protocol (không stratified)", tách
     khỏi số StratifiedGroupKFold trong báo cáo và không so trực tiếp.
- Báo cáo: precision/recall/F1 từng lớp, macro-F1, accuracy, confusion matrix 3×3,
  FPR per-class (benign→xss và benign→sqli là 2 FPR riêng), `fp_checks_html`,
  fold validity summary (§ trên).
- **Không tuyên bố tổng quát hóa trên family chưa gặp** — mọi số gắn với tập
  family trong dataset.

### 9.5 So sánh model v1.0 vs v1.1 + rollback

- **Giữ artifact v1.0:** export `model.joblib` + `metrics.json` từ container
  hiện tại sang `artifacts/v1.0/` (host, gitignore như hiện tại); model mới vào
  `artifacts/v1.1/`. Chọn version bằng env `ML_MODEL_DIR` — không ghi đè.
- **Không so binary-F1 với macro-F1 như cùng metric.** So sánh hợp lệ:
  (a) v1.0 binary OOF (F1 0.9076, FPR 1.68% — số baseline đã có);
  (b) v1.1 OOF 3-class macro-F1 + per-class; (c) **slice so sánh được:** từ
  v1.1 OOF tính binary benign-vs-(sqli∪xss) để đặt cạnh (a) với cùng protocol.
- **Phân biệt OOF validation vs end-to-end corpus evaluation:** OOF = quality
  của model trên dataset; corpus run = enforcement end-to-end. Không trộn.
- **Regression trên 26 case SQLi:** subset SQLi của RUN-A/RUN-B (v1.1) đối chiếu
  từng ô với baseline `2af841ab`/`4e4a7f2d` (v1.0) — chênh lệch được phép chỉ
  nằm trong biến đổi model version; nếu mismatch, vào §14 gate.
- **Tiêu chí chấp nhận v1.1 (v3.1 — bỏ heuristic "macro-F1 ≥ binary-F1 − 0.05"
  của v3; hai metric khác định nghĩa không được ghép thành một phép so):**
  mỗi tiêu chí dưới đây là ngưỡng độc lập, giải thích được và kiểm chứng được
  từ metrics.json / run evidence; **toàn bộ phải pass đồng thời:**

  | # | Tiêu chí | Ngưỡng | Căn cứ giải thích |
  |---|---|---|---|
  | A1 | Macro-F1 (OOF StratifiedGroupKFold) | ≥ 0.80 | 3 lớp + fold family-disjoint; 0.80 = ngưỡng chấp nhận được cho classifier dựa corpus synthetic nhỏ, vẫn để chống "F1 đẹp ảo" khi cân bằng lớp thay đổi |
  | A2 | Per-class F1 | benign ≥ 0.85, sqli ≥ 0.75, xss ≥ 0.70 | benign là lớp đa số (dễ đạt); sqli là lớp kế thừa v1.0 (F1 0.9076 binary) nên ngưỡng tương đương recall v1.0 giảm nhẹ do tách 3 lớp; xss là lớp mới nhỏ — ngưỡng thấp hơn có chủ đích, số thực tế vẫn được báo nguyên trạng |
  | A3 | FPR benign→sqli (OOF) | ≤ 5% | giữ continuity với FPR 1.68% của v1.0 — cho phép lệch do thay đổi protocol |
  | A4 | FPR benign→xss (OOF) | ≤ 5% | cùng logic A3, lớp mới |
  | A5 | Binary benign-vs-attack OOF slice (tính từ predictions 3-class: P(attack)=P(sqli)+P(xss) ≥ τ) | F1 ≥ 0.85 **và** được báo cạnh số v1.0 **không tuyên bố so sánh trực tiếp** | cùng định nghĩa metric (binary F1) nên đặt cạnh được; nhưng tập mẫu khác (n≈400 vs 312) nên là so sánh tham chiếu, không phải paired test — thực nghiệm same-sample duy nhất là regression 26 case (A6) |
  | A6 | SQLi regression 26 case end-to-end | mỗi case (config, PL) phải cho **cùng outcome** với baseline v1.0, trừ số lệch do threshold policy (tự động phân tích: nếu flip, kiểm xem attack-score tại threshold 0.5 có đổi polarity không); mọi flip không giải thích được bằng threshold = **fail** | đây là phép same-sample duy nhất, so từng ô |
  | A7 | FP-checks HTML (§9.3) | ≥ 90% pass | trực tiếp đo FPR trên benign HTML |

- **Phân biệt 3 loại evaluation (v3.1 làm rõ):** *OOF validation* = chất lượng
  model trên dataset (A1–A5, A7); *end-to-end corpus evaluation* = enforcement
  qua stack thật (A6, RUN-A/B); *external holdout* = dataset ngoài (Kaggle —
  phần mở rộng §15, không điều kiện duyệt X-phase). Không trộn số giữa ba loại.
- **Đạt A1–A7 → dùng v1.1 cho X5. Không đạt một tiêu chí nào → rollback
  `ML_MODEL_DIR` về v1.0** (artifact nguyên vẹn), XSS chỉ đo CRS + ghi "ML miss
  XSS" là kết quả phân tích (phương án B của v2 vẫn giữ được như fallback);
  rollback được ghi vào report với lý do từng tiêu chí fail.

---

## 10. API Contract (`/score` multi-class) — cần review nhóm

**`docs/interfaces.md §3` là shared contract — mọi thay đổi qua PR review nhóm.**

```jsonc
POST /score {"text": "..."} →
{
  "label": "benign | sqli | xss",        // mở rộng từ benign|malicious
  "score": {"benign": 0.07, "sqli": 0.90, "xss": 0.03},  // per-class proba
  "model_version": "lr-tfidf-3cls-1.1",
  "degraded": false                      // true = fallback regex stub
}
```

**Enforcement policy (v3.1 — sửa sai sót v3):** v3 từng viết "block khi
`label ∈ {sqli,xss}` (tương đương `proba[sqli]+proba[xss] ≥ threshold`)" —
**hai điều kiện KHÔNG tương đương trong mọi trường hợp:**

- `argmax = benign` ⇒ `P(benign) ≥ P(sqli)` **và** `P(benign) ≥ P(xss)` — không
  suy ra `P(sqli)+P(xss) < τ`. Ví dụ: `P(benign)=0.48, P(sqli)=0.27, P(xss)=0.25`
  → argmax=benign nhưng attack-sum=0.52 ≥ 0.5: **argmax không chặn, sum chặn**.
- Chiều ngược: `argmax ∈ {sqli,xss}` ⇒ `P(attack) ≥ P(benign)` ⇒ sum ≥ 0.5 —
  với τ=0.5 argmax-chặn thì sum cũng chặn (sum policy chỉ **nhạy hơn**, không
  có trường hợp argmax chặn mà sum không chặn tại τ=0.5).

| Phương án | Ưu | Nhược |
|---|---|---|
| **P1 — attack-sum policy (khuyến nghị):** block ⇔ `P(sqli)+P(xss) ≥ τ`; `label` (argmax) chỉ dùng để **phân loại loại tấn công** trong evidence/report | liên tục với v1.0 (P(attack) của model binary ≈ P(sqli)+P(xss) của model 3-class khi hành vi không đổi) → threshold sweep và regression 26 case so được theo cùng quy tắc; chặn được attack phân tán xác suất (mỗi lớp dưới 0.5 nhưng tổng cao) | tại τ=0.5 nhạy hơn argmax → FP có thể tăng; bù bằng sweep_thresholds trên chính policy này |
| **P2 — argmax-label policy:** block ⇔ argmax ≠ benign | FP thấp hơn tại cùng τ | mất continuity với v1.0; sót attack xác suất phân tán; threshold semantics khác binary → regression 26 case không đối chiếu được 1-1 |

**Khuyến nghị v3.1: P1.** `threshold` mặc định 0.5 — **giữ nghĩa cũ của v1.0**
("xác suất attack ≥ 0.5 ⇒ block"). `label` trong response = argmax toàn bộ 3
lớp; khi block, evidence ghi thêm `attack_class` = argmax giữa sqli/xss.

**Đồng bộ toàn hệ thống theo P1 (v3.1):**
- `/score` trả đủ per-class proba (consumer tự tính sum khi cần);
- proxy enforcement dùng `P(sqli)+P(xss) ≥ ML_THRESHOLD` (không dùng argmax);
- `sweep_thresholds.py` đổi sang sweep trên attack-sum (báo cả hai policy để
  so sánh — cột riêng, không gộp);
- evidence JSONL ghi đủ `scores {benign, sqli, xss}` + `attack_score = sqli+xss`
  + `threshold` + `decision` theo P1;
- report/tables ghi rõ "block theo attack-sum τ=0.5" — mọi số enforcement sau
  này gắn với policy này, không mơ hồ.

**Fail-open/fail-closed (so sánh, khuyến nghị):**

| Tình huống | Fail-open (cho qua) | Fail-closed (chặn) |
|---|---|---|
| prediction raise / score NaN | không false-positive, nhưng attack lọt | chặn sai benign nếu model lỗi |
| model không load → stub | hiện trạng: stub regex chấm điểm (degraded) | chặn toàn bộ → lab chết |

**Khuyến nghị v3:** model-load-fail giữ hiện trạng (stub regex, mở rộng stub
regex nhận diện thêm `<script`/`onerror` → `stub-0.2-3cls`, `degraded:true` —
hành vi giống v2, không tăng tính chặn); prediction-error **fail-closed** (403 +
evidence `error`) — ưu tiên bảo mật, FP do lỗi hệ thống được ghi rõ trong evidence
và tách khỏi FP thực nghiệm. *(Đây là quyết định mở — §18.)*

---

## 11. Runner Design

Thay đổi `scripts/run_experiment.py` (owner: Huỳnh):

1. `load_corpus`: path allowlist + `/comment`, `/comment-escaped`; đọc + validate
   `vuln`/`family`/`expected_waf_outcome`/`expected_app_effect`; adapter v1/v2.
2. Oracle select theo vuln: SQLi → `semantic_effect` (row-based, giữ nguyên);
   XSS → `reflected` (HTTP) + `execution_status` (mặc định unverified, được
   verify step nâng lên).
3. `detected` → `rule_families` từ rule ID thật (§8.2); block-gate giữ nguyên
   (949110 hoặc ML decision).
4. `summarize`/`summarize_by_technique` thêm chiều `vuln`: metrics per-vuln ×
   per-technique × per-config × per-PL; `true_bypass_xss` theo §7.3; pending
   (`execution_unverified`) report riêng, không nhập mẫu số metrics.
5. Output thêm `pending_browser_verification.json` (danh sách bộ
   (case_id, configuration, PL) cần WAF-path browser verification — sinh từ
   kết quả RUN-A/B) → input của `verify_xss_execution.py --mode waf-path`.
6. Direct control cho XSS case: gửi cả `/comment` **và** `/comment-escaped`
   (control check 2 chiều — §7.1).
7. **RUN-B bỏ probe ML-only standalone (v3.1):** hiện trạng runner gửi
   `via_ml` cho **mọi** run kể cả `--crs-backend ml` [AUDIT
   `run_experiment.py:407`] — trong RUN-B (hybrid) probe này trùng lặp
   (ML-only đã được RUN-A đo). Thiết kế v3.1: RUN-B chỉ gửi
   `direct + hybrid chain`; RUN-A giữ `direct + CRS-only + ML-only`. Nếu
   implementation giữ nguyên hành vi cũ thì tổng lượt tăng lên 648 — **bắt
   buộc đếm lại theo code thật khi chốt** (§12.1 footnote).
8. **Browser verification 2 chế độ (v3.1):** `scripts/verify_xss_execution.py`
   hỗ trợ `--mode app-control` (trực tiếp `:8080`, chạy trước RUN — gate R6)
   và `--mode waf-path --config {crs_only|ml_only|hybrid} --pl {1|2|3}` (truy
   cập đúng endpoint WAF đã đánh giá, chạy sau RUN-A/B — R7); evidence JSON
   theo §7.4.
9. **Enforcement policy P1 (§10):** proxy + evidence + sweep đều dùng
   attack-sum `P(sqli)+P(xss) ≥ τ`.

---

## 12. X5 Experiment Matrix (giải quyết Vấn đề F — số chính xác)

### 12.1 Bảng run matrix (v3.1 — đếm đúng từng loại lượt)

| Đại lượng | Giá trị | Ghi chú |
|---|---|---|
| Case SQLi cũ | 26 | 15 mal + 11 ben, không đổi [AUDIT] |
| Case XSS mới (mục tiêu) | 10 | 4 ben + 6 mal — chốt tại impl review |
| Tổng case | 36 | |
| Paranoia levels | 3 | PL1, PL2, PL3 |
| Cấu hình WAF | 3 | CRS-only / ML-only / Hybrid CRS→ML→app |
| **Run thực tế (run-ID)** | **2** | mỗi run-ID cover nhiều path — xem bảng dưới |
| **Case-rounds (tổng)** | **216** | 36 case × 3 PL × 2 run-ID |
| **Direct-control requests (tổng)** | **216** | 1 direct / case-round / run-ID (108 RUN-A + 108 RUN-B) |
| **WAF case executions (tổng)** | **324** | RUN-A: 216 (108 CRS-only + 108 ML-only); RUN-B: 108 (hybrid) |
| **Tổng HTTP requests** | **≈540** | 324 WAF + 216 direct (số chính xác 540) |
| Lượt browser verify | tập targeted (§7.2) | app-control ≤ 12 (trước RUN); WAF-path ≤ 15 (sau RUN) — không vào matrix request |

⚠️ **Tránh nhầm số 216:** giá trị 216 xuất hiện ở **2 nghĩa khác nhau** —
(1) tổng case-rounds (36×3×2) và (2) tổng direct-control requests (1 direct mỗi
case-round) — trùng số một cách trùng hợp, **không** phải cùng một phép đếm,
và **không** phải tổng WAF case executions (324).

**Đếm per run-ID:**

| run-ID | Case-rounds | Direct-control | WAF executions | Chi tiết WAF | HTTP requests |
|---|---:|---:|---:|---|---:|
| **RUN-A** `--crs-backend direct --levels 1 2 3` | 108 | 108 | 216 | CRS-only 108 + ML-only 108 | 324 |
| **RUN-B** `--crs-backend ml --levels 1 2 3` | 108 | 108 | 108 | Hybrid 108 | 216 |
| **Tổng** | **216** | **216** | **324** | 3 cấu hình × 108 | **540** |

- RUN-A = direct + CRS-only + ML-only; RUN-B = direct + Hybrid (v3.1 — RUN-B
  **không** gửi probe ML-only standalone; lý do và footnote code hiện trạng
  xem §11.7). Mỗi case-round RUN-A mất 3 request (direct + 2 WAF path), RUN-B
  mất 2 (direct + chain).
- → 2 run-ID × 3 PL × 3 cấu hình = đủ toàn ma trận. **Số "6 runs" trong v2 là
  sai/phép tính mơ hồ — đã sửa.**

**[UNVERIFIED] Footnote implementation:** runner hiện tại gửi `via_ml` trong cả
ml-backend mode [AUDIT `run_experiment.py:407`] — nếu giữ nguyên khi RUN-B chạy,
số thực tế sẽ là: RUN-B WAF executions 216, tổng HTTP 648. v3.1 chọn phương án
đếm theo thiết kế (RUN-B bỏ probe); khi implement, con số từ `results.csv` là
chân lý — phải đối chiếu lại với bảng này và ghi lệch sót (nếu có) vào metadata.

### 12.2 Baseline vs run mới

| Run | Corpus | Model | Trạng thái |
|---|---|---|---|
| `20261026T100537Z-2af841ab` | 26 SQLi, PL1–3 | v1.0 | baseline có [AUDIT] |
| `20261026T100617Z-4e4a7f2d` | 26 SQLi, PL1–3 (hybrid) | v1.0 | baseline có [AUDIT] |
| RUN-A (mới) | 36 (26 SQLi + 10 XSS) | v1.1 | cần chạy |
| RUN-B (mới) | 36, hybrid | v1.1 | cần chạy |
| Regression SQLi | subset SQLi của RUN-A/B | v1.1 | đối chiếu 2 baseline trên |

### 12.3 Metadata bắt buộc mỗi run

`commit_hash`, `corpus_sha256` (từng cases.json), `model_artifact_sha256`
(model.joblib + metrics.json), `model_version`, `crs_version` (đọc từ image
config — hiện chưa có trong metadata cũ → **thêm**), `paranoia_level`,
`configuration` (crs_backend), `timestamp_utc`, `raw_evidence_location`.
(`metadata.json` hiện đã có 5/10 — [AUDIT] `run_experiment.py:599-620`; thiếu
crs_version → bổ sung.)

**Demo payload: chỉ chọn sau khi RUN-A/RUN-B có số thực nghiệm** — payload demo
được trích từ evidence, không chọn trước.

---

## 13. Evidence và Reproducibility

- Giữ nguyên cấu trúc `results/raw/experiments/<run-id>/` + `results/raw/browser/<run-id>/`.
- `metadata.json` mở rộng (§12.3). Mọi run ghi `execution_status` per case;
  browser evidence JSON theo §7.4.
- `.gitignore` tiếp tục loại `results/raw/**`, `*.joblib` — evidence nằm máy local,
  tái lập bằng lệnh trong README (đã là quy ước nhóm [AUDIT]).
- Bảng tổng hợp mới: `results/tables/bypass-matrix-v3-<date>.md` per-vuln ×
  per-technique × per-config × per-PL + SVG mới.

---

## 14. Regression Checklist (bảng đầy đủ)

| Test | Mục đích | Lệnh / phương pháp | Expected | Evidence lưu | Pass/Fail | Khi nào |
|---|---|---|---|---|---|---|
| **R0** | Baseline dev pre-merge | chạy R1+R2+R3 trên `dev` hiện tại, lưu output | pass trên dev nguyên trạng | log output trong worktree report | ✅ trước merge | **TRƯỚC merge** |
| **R1** | Unit tests CRS hiện có | `python -m unittest discover -s waf-crs -p "test_*.py" -v` | pass | log | ✅ | dev + post-merge |
| **R2** | Unit tests web-app (cũ+5 mới XSS) | `python -m unittest discover -s web-app -p test_app.py -v` | pass | log | ✅ | dev (R2a: chỉ test cũ) + sau X1 (R2b: full) |
| **R3** | Smoke PL1 đối chiếu WAF↔App | `python waf-crs/run_integrated_smoke.py --levels 1` | PL1 detect 100%, FPR 0% (baseline 20261025T172523Z) | evidence run | ✅ | dev + post-merge + post-rebuild |
| **R4** | SQLi regression CRS-only | RUN-A subset SQLi, PL1–3 vs `2af841ab` | từng ô khớp (block 13/13/15, FPR 9.1/9.1/72.7, bypass 0) | results.json diff | ✅ | sau X1–X4 |
| **R5** | SQLi regression hybrid (v1.1) | RUN-B subset SQLi vs `4e4a7f2d` | khớp trong sai số model version | results.json diff | ✅ | sau X4 |
| **R6** | XSS app control (v3.1) | AC-1..4 (unit + direct HTTP) + browser **app-control** verification (§7.2) | /comment reflect; /comment-escaped escape; encoded/2-lượt đúng §6.3; app-control browser: /comment executed, control not_executed | test log + browser JSON (app_control) | ✅ | sau X1 |
| **R7** | XSS WAF-path browser verification (v3.1) | `scripts/verify_xss_execution.py --mode waf-path --config {crs_only\|ml_only\|hybrid} --pl {1\|2\|3}` trên pending list sinh từ RUN-A/B | executed=true chỉ ghi cho đúng bộ (case, config, PL) đã verify; pending list empty sau đó | browser JSON + screenshots (waf_path) | ✅ | **sau RUN-A/B** |
| **R8** | Multi-class `/score` | curl probe (sqli/xss/benign + HTML benign) | 3 label đúng; `degraded:false` | curl log | ✅ | sau X4 |
| **R9** | Test thay đổi từ `12e597b` | `python -m unittest discover -s waf-crs -p test_integrated_smoke.py -v` **(file chỉ tồn tại SAU merge — không được yêu cầu trước merge)** | pass | log | ✅ | **SAU merge trong worktree (B0.5)** |
| **R10** | Docker healthcheck 4 service | `docker compose up -d --build --wait --wait-timeout 240 && docker compose ps` | 4 healthy | compose ps log | ✅ | sau mỗi rebuild |
| **R11** | Threshold sweep v1.1 | `python scripts/sweep_thresholds.py <run-A results.json>` | bảng TP/FP/F1/FPR theo threshold trên **attack-sum policy** (§10, có cột so sánh 2 policy); chốt 0.5 hoặc threshold mới | sweep output | ✅ | sau RUN-A |
| **R12** | FP-checks HTML model | metrics.json.fp_checks_html | ≥90% pass | metrics.json | ✅ | sau X4 |
| **R13** | Full integration regression | R1–R12 tất cả pass + RUN-A/B complete (`incomplete=0, control_invalid=0`) | matrix 3 config × 3 PL đủ | run evidence | ✅ | trước merge dev→main |

---

## 15. Timeline và Dependency (2 tuần)

Legend: ⏸ = chờ dependency; ∥ = chạy song song được.

| Ngày | Task | Owner | Depends on |
|---|---|---|---|
| D1 ⏸ | B0.1–B0.2: lưu diff, baseline dev (R0, R1, R2a, R3) | Hiếu | duyệt chủ dự án |
| D1 ⏸ | B0.3–B0.6: worktree merge thử + conflict + R9 + R10 | Hiếu + Huy | B0.2 pass |
| D1–2 ∥ | X1: `/comment` + `/comment-escaped` + oracle + tests (R6) | Hiếu | **merge feature/crs xong** |
| D1–2 ∥ | X2: 10 case XSS schema v2 + README corpus | Long | schema §5 duyệt |
| D2–3 ∥ | X3: runner v2-adapter + rule-families + verify_xss_execution.py | Huỳnh | X1 endpoint (oracle select), X2 (schema) |
| D3–4 ∥ | X4: dataset + `lr-tfidf-3cls-1.1` + export v1.0 artifacts + FP checks (R8, R12) | ĐVH | X2 (family taxonomy), review contract §10 |
| D4 ∥ | Duyệt `docs/interfaces.md` v2 (schema + API) — PR review nhóm | Hiếu chốt, cả nhóm | X1–X3 draft |
| D4–5 ⏸ | RUN-A + RUN-B (X5) → R4, R5, R11 | Huỳnh | **X1+X2+X3+X4 xong (R6, R8 pass)** |
| D5–6 ⏸ | R7: WAF-path browser verification trên pending list + chốt metrics không-pending | Huỳnh | **RUN-A/B xong** (v3.1 — R7 phụ thuộc RUN, không phải X5 chạy sau R7) |
| D6 ⏸ | R13: full integration regression gate | Huỳnh | **R7 + pending list empty** |
| D6–8 ∥ | CRS hardening (exception hẹp theo rule-id evidence, cả 941 FP nếu có) + before/after | Huy + Hiếu | RUN-A/B |
| D6–8 ∥ | Kaggle external holdout (chỉ nếu dư thời gian — không chặn deliverables chính) | ĐVH | X4 |
| D9–10 **buffer** | resolve regression fail, re-run experiments, re-run WAF-path browser verification | cả nhóm | kết quả D4–6 |
| D9–13 ⏸ | Báo cáo cuối + slide + demo (payload demo trích từ evidence; demo Playwright sống) | cả nhóm | R13 pass |
| **Cuối** ⏸ | merge dev→main + tag | Hiếu | **R13 pass toàn bộ** |

**Luật dependency cứng (v3.1 — không còn vòng lặp):** X5 (RUN-A/B) không chạy
trước khi runner + corpus + model + oracle sẵn (R6, R8 pass); **R7 chạy SAU
RUN-A/B** (pending list sinh từ kết quả run — đúng hướng X5→R7); R13 chỉ chạy
sau khi R7 xong và pending list empty; merge dev→main không chạy trước R13.

---

## 16. Risk Register

| # | Rủi ro | Xác suất | Tác động | Mitigation |
|---|---|---|---|---|
| 1 | Conflict merge feature/crs phức tạp hơn dự kiến (5 files changed-in-both) | TB | chậm D1–2 | worktree thử (B0.3); conflict đã được xác định trước theo hunk |
| 2 | Model 3-class tăng FPR benign HTML / tiếng Việt có `<` | TB | méo FPR, mất công tin | FP-checks HTML (§9.3) + sweep_thresholds + rollback v1.0 |
| 3 | ML miss XSS hoàn toàn (corpus model nhỏ) | TB | ML-only không chặn XSS | là kết quả phân tích có giá trị; fallback phương án "XSS chỉ đo CRS" trong acceptance v1.1 |
| 4 | CRS chặn XSS chỉ bằng transport rule (không 941) | TB | cần phân tích rule-family đúng | §8.2 phân loại theo ID thật — thiết kế đã xử lý |
| 5 | Playwright flakiness / dialog chặn headless | TB | R7 chậm | tín hiệu chính = DOM/title, dialog chỉ phụ; timeout + retry 2 lần |
| 6 | Family nhỏ khiến fold thiếu lớp | TB | validation fail | 4 kiểm tra hợp lệ §9.4; nếu bắt buộc GroupKFold → đánh dấu protocol riêng, không coi là tương đương |
| 7 | `execution_unverified` sót lại khi chốt số | TB | true bypass không đủ bằng chứng | pending list bắt buộc empty trước R13 (§11.5) |
| 8 | Kẹt PL3 sau smoke (đã từng xảy ra [AUDIT implementation-status]) | TB | run sai PL | check `tx.blocking_paranoia_level` trước RUN |
| 9 | Kaggle time-box tràn | TB | ảnh hưởng deliverables chính | D6–8 song song + hard gate: bỏ nếu trễ |
| 10 | Thuật ngữ contract đổi làm runner/proxy lệch nhau | TB | fail end-to-end | PR review interfaces.md trước implementation (D4) |

---

## 17. Acceptance Criteria (điều kiện X-phase được coi "hoàn thành")

1. R0–R13 pass; pending-browser list empty **(v3.1: R7 WAF-path verification
   xong sau RUN-A/B — đúng thứ tự, không phụ thuộc vòng)**.
2. Matrix đầy đủ: 3 config × 3 PL × (SQLi + XSS), `incomplete=0`,
   `control_invalid_total=0` mỗi run.
3. Có ≥1 case `true_bypass` **SQLi** (decode-double — theo kế hoạch gốc) và/hoặc
   ≥1 case `true_bypass_xss` với **WAF-path browser evidence `executed` của đúng
   bộ (case, config, PL)** (§7.3) — nếu không đạt, kết quả âm phải được phân
   tích cơ chế (kết quả âm có giá trị, nhưng phải loại trừ
   execution_unverified).
4. Bảng per-vuln × per-technique × per-config có số thật từ run.
5. Model v1.0 artifact nguyên vẹn; v1.1 đạt tiêu chí §9.5 hoặc rollback có ghi.
6. Báo cáo + slide có: detection/blocking/effect tách bạch, rule hotlist,
   hardening recommendations, demo payload trích từ evidence thật.
7. dev→main merge chỉ diễn ra sau mục 6.

---

## 18. Các quyết định cần chủ dự án duyệt

| # | Quyết định | Khuyến nghị v3.1 | Phương án khác |
|---|---|---|---|
| Q1 | Restore `scripts/requirements-attack.txt` | restore (nội dung gốc nguyên văn đã lưu §4.1) | giữ cheat-sheet, chuyển tool list sang scripts/README.md |
| Q2 | Merge feature/crs vào dev tại D1 qua worktree | merge sau khi R9+R10 pass | defer đến sau X-phase (tăng rủi ro conflict với X1) |
| Q3 | Fail-closed prediction-error ở ML proxy | fail-closed + evidence | fail-open (giữ disponibilidad) |
| Q4 | Contract `/score` 3-class | chấp nhận, PR review nhóm | giữ binary label + thêm field `attack_type` |
| Q5 | Số case XSS 10 (4 ben/6 mal) | chốt tại impl review | mở rộng 12–14 nếu FPR-check cần thêm benign |
| Q6 | Thuật ngữ model version `lr-tfidf-3cls-1.1` | chốt | `lr-tfidf-multi-1.1` |
| Q7 | Kaggle holdout | chỉ khi buffer dư | cut khỏi timeline nếu trễ |
| **Q8** (v3.1) | **RUN-B bỏ probe ML-only standalone** (runner hiện gửi via_ml cả ml-backend [AUDIT `run_experiment.py:407`]) | **bỏ probe trong RUN-B** — RUN-A đã đo ML-only; RUN-B = direct + hybrid (matrix §12.1) | giữ probe (tổng HTTP 648, số dư phải đối chiếu lại toàn bộ bảng đếm) |

---

## 19. Danh sách chưa xác minh (không suy đoán)

1. **Hành vi CRS 941xxx trên từng payload XSS cụ thể của corpus mới** — chưa chạy
   thực nghiệm; mọi số WAF-1..3 là dữ liệu đo, không phải kỳ vọng.
2. **Hành vi model v1.0 với payload XSS** (`<script>` có thể đã lọt benign) —
   chưa đo; sẽ ghi vào phân tích so sánh nếu xảy ra.
3. **Số mẫu dataset v1.1 cuối cùng sau dedup** — chỉ có ước tính ≈390–410.
4. **Khả năng Playwright hoạt động trên máy lab nhóm hiện tại** (chưa cài, chưa
   chạy thử — tool nằm ngoài compose, phải cài host-side).
5. **Fold-balance thực tế của StratifiedGroupKFold với family mới** — phụ thuộc
   dataset thật; phải qua 4 kiểm tra hợp lệ §9.4 trước khi số được dùng.
6. **Conflict text-level chính xác** của 5 files changed-in-both — merge-tree chỉ
   xác định *file-level*, chưa liệt kê hunk.
7. **Hành vi `/comment-escaped` trên Werkzeug khi query chứa `%2F`** — edge case
   path-decoding, sẽ có trong test AC-4 nhưng chưa chạy.
8. **Hành vi RUN-B thực tế với probe `via_ml`** — v3.1 thiết kế là bỏ probe
   (Q8); nếu implementation giữ nguyên hành vi cũ [AUDIT `run_experiment.py:407`],
   tổng lượt là 648 thay vì 540 — phải đối chiếu lại toàn bộ bảng đếm §12.1
   từ `results.csv` thật.
9. **Hành vi `sweep_thresholds.py` sau khi chuyển sang attack-sum (§10)** —
   chưa implement; bảng sweep với 2 policy là output mong muốn, chưa có số.

*(Ghi chú v3.1: mục 8 cũ của v3 — "nội dung gốc chính xác của
`requirements-attack.txt`" — đã chuyển sang xác minh: nội dung HEAD được trích
nguyên văn tại §4.1; chưa đối chiếu với commit `1dcf7d0` nguyên trạng do ràng
buộc read-only, xem ghi chú phạm vi tại §4.1.)*

---

## 20. Kết luận

v3.1 giải quyết đủ 6 vấn đề bắt buộc (A–F) với thiết kế có cơ chế kiểm chứng
riêng — oracle 2 tầng hợp lệ per-case với 2 chế độ browser tách bạch (A), schema
thống nhất tách technique/family + WAF outcome vs app effect (B), ba khái niệm
tách bạch với phân loại rule thật (C), 3-class với naming đúng + rollback + tiêu
chí chấp nhận kiểm chứng được (D), hai phép kiểm thử app-vs-WAF tách rời (E),
run matrix đếm đúng từng loại lượt — 324 WAF case executions / 216 direct
controls / ≈540 HTTP (F) — và 9 chỉnh sửa review v3→v3.1 (§21). Tài liệu **đủ
điều kiện để duyệt Phase 0** sau khi chủ dự án quyết Q1–Q8.

---

## 21. Đối chiếu v3 → v3.1 (9 chỉnh sửa theo review chủ dự án)

| # | Vấn đề được nêu | Chỉnh sửa v3.1 | Mục |
|---|---|---|---|
| 1 | X5 accounting sai: "216" bị dùng cho 2 nghĩa khác nhau (case-rounds và requests) | Tách bạch 4 phép đếm: 216 case-rounds, 216 direct-control requests, 324 WAF case executions, ≈540 HTTP total — với bảng per run-ID và footnote hiện trạng runner (probe via_ml trong RUN-B → nếu giữ nguyên là 648, Q8 quyết định) | §12.1, §11.7, Q8 |
| 2 | Claim sai "argmax ≠ benign ≡ P(sqli)+P(xss) ≥ τ" | Phản biện 2 chiều với ví dụ số; so sánh P1 (attack-sum, khuyến nghị) vs P2 (argmax); đồng bộ proxy/evidence/sweep/report theo P1; τ=0.5 giữ nghĩa v1.0 | §10 |
| 3 | Browser verification một mode — không tách được bằng chứng app vs WAF | Tách `app_control` / `waf_path` trong evidence; `true_bypass_xss` bắt buộc WAF-path của đúng (case, config, PL); R6 = app-control (trước RUN), R7 = WAF-path (sau RUN-A/B) | §7.1–7.4, §14 |
| 4 | Heuristic "macro-F1 ≥ binary-F1 − 0.05" không kiểm chứng được | Thay bằng bảng A1–A7: ngưỡng độc lập per-metric có căn cứ; binary slice báo cạnh v1.0 không so trực tiếp; phân biệt OOF / end-to-end / external holdout | §9.5 |
| 5 | Timeline có vòng lặp R7 ↔ X5 (R7 "sau X1+X3" nhưng X5 cần R7) | Dải lại: X5 cần R6+R8; R7 chạy sau RUN-A/B trên pending list sinh từ run; R13 sau R7; luật dependency cứng ghi rõ | §15 |
| 6 | `render_template_string(user_text)` nguy cơ SSTI + endpoint đủ ràng buộc an toàn chưa ghi | Template cố định + raw sink nối giá trị; cấm input làm template source; ghi ràng buộc lab-only (loopback compose network, host port 127.0.0.1) | §6.1 |
| 7 | `expected_app_effect` hình như phụ thuộc WAF | Ghi rõ: mô tả hiệu ứng direct control, độc lập WAF; cách so expected-vs-actual theo 2 đường (direct control / WAF path) tách bạch | §5.2 |
| 8 | StratifiedGroupKFold: kiểm tra và fallback chưa đủ chặt | 4 kiểm tra bắt buộc (family không chia đôi, đủ 3 lớp mỗi fold, đếm family độc lập per class, không thể tạo 5 fold hợp lệ → báo cáo + giảm fold); fallback GroupKFold KHÔNG tương đương, phải đánh dấu riêng protocol | §9.4 |
| 9 | "Nội dung gốc requirements-attack.txt" chỉ là tuyên bố chưa xác minh | Trích nguyên văn 6 dòng (từ `git diff` HEAD) vào chính tài liệu + ghi rõ phạm vi xác minh; bỏ khỏi danh sách chưa xác minh | §4.1, §19 |
