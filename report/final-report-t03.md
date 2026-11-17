# T03 — WAF học máy và kỹ thuật né tránh: tái lập tấn công đối kháng (báo cáo cuối)

**Chương:** C4 (WAF bypass) · C5 · **Ngày:** 15/11/2026 · **Trạng thái G3:** đã ký (owner decision 15/11, `results/gates/G3-readiness-20261113.md`)

Mọi số liệu trong báo cáo này đều dẫn về run ID / bảng trong repo. Model nền đang
phục vụ là `lr-tfidf-3cls-1.1` (v1.1); v1.4 là candidate chưa promote; v1.5/v1.5.1
chỉ là thí nghiệm so sánh dataset.

---

## 1. Mục tiêu và phạm vi

- **Mục tiêu:** hiểu vì sao WAF dựa trên signature và WAF dựa trên ML bị vượt qua;
  tái lập các nhóm kỹ thuật né tránh đã công bố trên WAF mã nguồn mở; đo tỉ lệ
  bypass theo từng nhóm kỹ thuật; giải thích cơ chế gốc của bypass.
- **Phạm vi:** ModSecurity + OWASP CRS (signature) và WAF ML tự huấn luyện trong
  lab Docker tự dựng.
- **Ngoài phạm vi (theo đề bài):** WAF thương mại / WAF-as-a-Service đang chạy
  production (AdvSQLi, Qu et al. 2024 chỉ dùng làm tài liệu tham chiếu kỹ thuật).
- **Kỹ thuật thuộc phạm vi (đúng 4 nhóm giáo trình C4):** HTTP Parameter
  Pollution/Fragmentation (HPP), double encoding, case variation + SQL comment,
  parsing discrepancy giữa WAF và ứng dụng.

## 2. Lab setup

| Thành phần | Chi tiết |
|---|---|
| Database | MySQL 8.4 (container `waf-db`, không publish port) |
| Ứng dụng | Flask + PyMySQL, `:8083` (trực tiếp) — có lỗ hổng SQLi/XSS có chủ đích, kèm reference response để đo effect |
| WAF signature | ModSecurity + OWASP CRS, `:8081`, paranoia level PL1–PL3 chuyển qua biến `CRS_PL` của Compose |
| WAF ML | TF-IDF `char_wb` (1,2) + LogisticRegression 3 lớp, threshold 0.5, `:8082` |
| Cấu hình đo | 3 chế độ: CRS-only, standalone ML, hybrid CRS→ML |

**Model nền v1.1** (`waf-ml/artifacts/v1.1/`): sklearn 1.7.1, train trên 426 dòng
lab (benign 223 / sqli 146 / xss 57, 22 families). Chỉ số OOF trên tập train:
macro-F1 0.929; gate chấp nhận A1–A5 + A7 PASS, A6 được xử lý end-to-end bằng
regression 26-case SQLi (78/78 outcome khớp baseline, `results/gates/R13-checklist-20261112.md`).

**Corpus kiểm thử:** 37 case đóng băng, hash khóa — 11 case-comment, 8
double-encoding, 9 HPP, 9 parsing-discrepancy (SQLi + XSS, 22 malicious + 15
benign mỗi PL). `hpp-mal-004` được thêm ở commit `b5769a5`. Corpus chỉ dùng để
test, không dùng train. **Giới hạn phải khai báo:** 22/37 input trùng exact với
bộ train lab (`results/tables/v1.5.1-source-weighted-kaggle-20261114.md` §Leakage).

## 3. Phương pháp đo

- **RUN-A** `20261114T112812Z-1f47c60b` (CRS direct + standalone ML) và **RUN-B**
  `20261114T113212Z-ee819911` (hybrid): mỗi run 111 hàng = 37 case × PL1–3;
  `incomplete=0`, `control_invalid_total=0`, pending-browser `[]`; SHA-256 của
  hai `results.json` được ghi và kiểm tra khớp trong
  `results/tables/g3-candidate-metrics-v1.4-37case-20261114.md`.
- **Bốn khái niệm tách bạch tuyệt đối** (yêu cầu xuyên suốt đề bài "không liệt kê
  payload" + báo cáo trung thực):
  - `detected`: WAF/ML có gán nhãn tấn công;
  - `blocked`: quyết định chặn hiệu lực trên đường đi đó;
  - `true_bypass`: payload qua WAF không bị chặn **và** ứng dụng tạo effect tấn
    công quan sát được, xác minh được (`semantic_effect=true`), có evidence liên
    kết request → WAF → app (G3 §6.3 amendment 15/11);
  - `pass_without_effect`: request đi qua nhưng không có effect — **không tính
    bypass**. Kết quả âm phải được phân tích cơ chế và loại trừ
    `execution_unverified`.
- So sánh baseline: toàn bộ 111 hàng của RUN-A/B v1.4 được đối chiếu per-case với
  run khóa v1.1 `20261113T105850Z-f4deea31` / `20261113T110057Z-5a65730f` — 0 lệch
  quyết định WAF, HTTP status, app effect, true-bypass, outcome (đường ML-only
  chỉ khác nhãn đa lớp của `pd-mal-003`, quyết định hiệu lực không đổi).

## 4. Kết quả: tỉ lệ bypass theo nhóm kỹ thuật (sản phẩm riêng #1)

Nguồn: `results/tables/t03-final-synthesis-20261115.md`; mẫu số là số case
malicious của từng kỹ thuật mỗi PL: case-comment 8, double-encoding 5, HPP 5,
parsing-discrepancy 4 (tổng 22/PL).

| Kỹ thuật | CRS-only PL1/2/3 | Standalone ML PL1/2/3 | Hybrid PL1/2/3 |
|---|---|---|---|
| Case variation + SQL comment | 0/8 · 0/8 · 0/8 | 0/8 · 0/8 · 0/8 | 0/8 · 0/8 · 0/8 |
| Double encoding | 0/5 · 0/5 · 0/5 | 0/5 · 0/5 · 0/5 | 0/5 · 0/5 · 0/5 |
| HPP (case `hpp-mal-004`) | **1/5 · 1/5** · 0/5 | **1/5 · 1/5 · 1/5** | **1/5 · 1/5** · 0/5 |
| Parsing discrepancy | 0/4 · 0/4 · 0/4 | 0/4 · 0/4 · 0/4 | 0/4 · 0/4 · 0/4 |

Điểm chính:

- **Đúng một bypass thật duy nhất:** `hpp-mal-004` — ghi nhận ở CRS-only và hybrid
  PL1–PL2, và ML-only ở PL1–PL3. Các quan sát PL/config lặp lại **không phải các
  payload độc lập** — tỉ lệ bypass thật của cả corpus là 1/22 malicious case.
- **Double encoding: bypass rate 0%** — 2–4/5 case đi qua WAF ở PL1–2 nhưng chỉ
  đạt `pass_without_effect` (không có app effect); ở PL3 CRS chặn hết (4/4).
- **Parsing discrepancy: bypass rate 0%** — CRS bắt được (2–3/4 detected, blocked),
  không có case nào qua; 2 case benign của nhóm này thậm chí bị chặn 1 case ở
  PL2–PL3 (FP).
- **XSS: không có bypass** — case `xss-de-mal-001` PL1 đi qua CRS ở HTTP 200 nhưng
  browser oracle xác nhận payload **không thực thi** (`pass_without_effect`,
  `results/gates/R13-checklist-20261112.md` R7) — đúng chuẩn "effect phải được
  thực thi trên browser" cho XSS.

## 5. So sánh WAF signature vs WAF ML

| Khía cạnh | CRS (signature) | ML (TF-IDF + LR) |
|---|---|---|
| Bypass `hpp-mal-004` | Cho qua ở PL1–2, chặn ở PL3 (403; `921180`, `932350`, `949110`) | Cho qua ở mọi PL — attack score 0.276 (v1.1) / 0.250 (v1.4) < threshold 0.5 |
| Benign FP trong corpus | PL1: 0/15; PL2: 1/15 (rule `932350` match **tên tham số** `id`, trùng tên lệnh Unix); PL3: 10/15 | 0/15 trên corpus |
| Điểm mạnh | Chặn ch crisp các family trong rule set | Chặn tốt family đã học trong tập train |
| Điểm yếu | Blind spot ngữ nghĩa không có rule mô hình hóa | Yếu với biến thể ngoài phân phối dữ liệu train |
| Giá trị kết hợp | Lớp chặn trước (hybrid PL3: CRS chặn, ML không bị hỏi) | Lớp chặn sau cho payload signature bỏ lọt |

ML enforcement đã chạy thật từ 26/10/2026 trên `:8082` — mọi route ứng dụng được
chấm điểm, `score ≥ 0.5` → 403 (`report/midterm-giao-an.md`).

**Candidate v1.4** (chưa promote): metrics external tốt hơn rõ rệt — macro-F1
0.9960 trên HttpParams holdout 10,211 dòng chưa từng học (XSS F1 0.9886, benign
FPR 0) so với OOF in-sample 0.929 của v1.1; WAF-path trên corpus đóng băng 0 lệch
so với v1.1. Chưa đủ điều kiện promote vì: A1–A5 OOF/group **NOT EVALUATED**
(HttpParams/Mendeley không có family metadata, không dựng được family-disjoint
OOF); A7 HTML benign = 28/30 (93.3%, đạt ngưỡng 90%) với 2 FP
(`<code>SELECT</code>` 0.5508, `data-id='42'` 0.5040)
(`results/gates/v1.4-acceptance-audit-20261115.md`). v1.5/v1.5.1 (full Mendeley
1.485.549 dòng fit) kém hơn v1.4 trên cùng bộ test (XSS recall 123/177 và
171/177 so với 173/177) — chỉ là thí nghiệm so sánh dataset.

## 6. Đối chiếu bằng công cụ công khai (wafw00f, sqlmap --tamper)

Nguồn đầy đủ: `results/tables/tools-corroboration-20261115.md`; log thô
`results/raw/sqlmap/` (15/11/2026).

- **wafw00f v2.4.2:** phát hiện lab có WAF (phản ứng khác biệt 200 vs 403 với
  chuỗi tấn công) nhưng **không dò được vendor ModSecurity** — CRS trả 403 không
  kèm chữ ký vendor → mất lợi thế recon của kẻ tấn công.
- **sqlmap 1.10.11** (target `-p id`, `--level=2 --risk=1`, kỹ thuật B/E/U):

| Mục tiêu | UA | Tamper | Kết quả |
|---|---|---|---|
| App trực tiếp `:8083` | random | — | **INJECTABLE** (chứng minh app lỗ hổng, tool hoạt động) |
| CRS PL1 | sqlmap mặc định | — | blocked — 275× 403 (tool-detection UA rule) |
| CRS PL1 | trình duyệt | — | **INJECTABLE** — boolean-blind đi qua, 2060× 403 nhưng có payload qua và khai thác được |
| CRS PL1–3 | random | space2comment / charencode / between | toàn bộ blocked — mutation làm **tệ hơn** |

Ba điểm đối chiếu khớp corpus: (1) PL1 lộ blind spot thật, PL2–PL3 khép lại;
(2) mutation/obfuscation không phải cơ chế thắng — chính các biến đổi lại trúng
rule CRS; (3) UA của tool chỉ là tín hiệu mềm, dễ né bằng UA trình duyệt.

## 7. Khuyến nghị cấu hình CRS theo paranoia level (sản phẩm riêng #2)

Dữ liệu: bảng per-cell benign blocked của matrix 37-case (CRS-only) + sqlmap
matrix (mẫu benign lab nhỏ: 15 dòng corpus — cần đọc như chỉ báo, không phải
đo FPR production).

| PL | Bypass CRS-only | sqlmap | Benign blocked (corpus) | Khuyến nghị |
|---|---|---|---|---|
| PL1 | **Có** — `hpp-mal-004` (và boolean-blind sqlmap) | Qua | 0/15 | Không dùng làm lớp phòng thủ duy nhất |
| PL2 | **Có** — tautology vẫn qua CRS-only | Không qua | 1/15 (FP do tên param `id`) | **Cân bằng cho lab: PL2 + hybrid ML** |
| PL3 | Không — tautology bị chặn 403 | Không qua | 10/15 (66.7% corpus benign) | Môi trường ưu tiên chặn; bắt buộc tune FP theo endpoint/param |

Khuyến nghị cụ thể cho FPR PL3: rule `932350` match **tên tham số** `id` (trùng
tên lệnh Unix) — exception hẹp theo endpoint/param, không mở rộng giá trị
(`report/midterm-giao-an.md`, evidence PL3 FPR). Cấu hình cân bằng của lab:
**PL2 + hybrid** — PL2 giữ benign FP thấp, lớp ML bù các case CRS cho qua.

## 8. Cơ chế gốc của bypass (+10% — khác biệt parser, không chỉ liệt kê payload)

Case `hpp-mal-004`: request `GET /product?id=1%2B1&id=1`.

**Phép đối chứng single-parameter** (`results/gates/HPP-arithmetic-bypass-20261113.md`,
14/11, post-hoc) — cùng payload **không** nhân đôi tham số:

| Request | CRS PL2 | CRS PL3 | ML `/score` | Kết quả ML |
|---|---|---|---|---|
| `?id=1%2B1` (đơn) | 200, trả row 2 | 403 | text `1+1` | benign 0.778 / attack 0.210 |
| `?id=1%2B1&id=1` (nhân đôi = case gốc) | 200, `true_bypass` | 403 | text `1+1 1` | benign 0.724 / attack 0.266 |

Kết luận cơ chế — ba lớp:

1. **Khác biệt parser giữa WAF và ứng dụng (semantic gap):** CRS không có rule
   nào mô hình hóa biểu thức số học `1+1` (arithmetic tautology) ở PL1–2 — không
   phải lỗi HPP. Phép đối chứng chứng minh nhân đôi tham số **không thay đổi bất
   kỳ quyết định WAF nào**: cơ chế thật là CRS blind spot, `hpp-mal-004` chỉ là
   payload tình cờ dùng đúng format HPP.
2. **Ứng dụng thực thi khác WAF hiểu:** Flask/Werkzeug first-value-wins lấy
   `id="1+1"`; MySQL đánh giá `WHERE id = 1+1` → trả row 2 (bob) thay vì row 1
   (alice) — effect quan sát được, không có SQL error. WAF nhìn thấy chuỗi vô hại,
   DB nhìn thấy biểu thức — đúng loại parsing discrepancy mà WAFFLED
   (Akhavani et al., ACSAC 2025) mô tả.
3. **ML cũng blind vì lý do khác:** TF-IDF char n-grams chưa thấy pattern `1+1`
   trong tập train → attack score 0.210–0.276, dưới threshold 0.5 → cho qua. Đây
   là điểm yếu out-of-distribution của model, không phải lỗi threshold.

Nhãn `hpp` trong corpus giữ nguyên (hash khóa, quyết định G3 15/11 option (a));
report mô tả cơ chế đúng như trên.

## 9. Demo live (đã thực hiện 15/11/2026, lab PL1)

```
$ curl "http://127.0.0.1:8081/product?id=1%2B1&id=1"        # qua CRS PL1
HTTP 200  {"count":1,"id":"1+1","rows":[{"id":2,"username":"bob"}]}   # row 2 thay vì row 1 (alice)

$ curl "http://127.0.0.1:8083/product?id=1%2B1&id=1"        # app trực tiếp (không WAF)
HTTP 200  {"count":1,"id":"1+1","rows":[{"id":2,"username":"bob"}]}   # app lỗ hổng thật

# CRS chuyển PL3 (CRS_PL=3, recreate waf-crs), cùng request:
HTTP 403 Forbidden                                                   # WAF chặn
```

Reference `?id=1` trả row 1 (alice) — effect "trả nhầm row" chỉ xảy ra với payload
tautology. Sau demo, lab được khôi phục PL1 (đã verify trong container).

## 10. Giới hạn

1. **Corpus lab tự dựng:** 22/37 case trùng exact với data train lab → kết quả
   37-case với model v1.4 là một phần in-sample; không chứng minh generalization
   độc lập. Cần phiên bản train lab-overlap-free trước khi promote.
2. **OOF/group cho v1.4: NOT EVALUATED** — HttpParamsDataset và Mendeley không có
   family metadata; split ngẫu nhiên theo row không thỏa protocol family-disjoint.
   Kết quả OOF của v1.1 không chuyển giao được cho v1.4.
3. **Holdout XSS chỉ payload-level:** Mendeley safety-neutralized, không chứng minh
   XSS executable; browser evidence chỉ có trên corpus lab.
4. **sqlmap/wafw00f:** một lần chạy mỗi cell (PL × tamper) — mục tiêu là đối
   chiếu, không vét cạn; HPP/fragmentation không có tamper tương đương trong
   sqlmap (evidence nhóm HPP đứng trên corpus + single-parameter control).
5. **Benign set nhỏ (15 dòng corpus):** con số PL3 10/15 là chỉ báo trên lab,
   không ngoại suy FPR production.

## 11. Kết luận

- **Signature WAF (CRS):** bypass được ở PL1–2 bằng ngữ nghĩa đơn giản, không cần
  obfuscation — payload tautology không có rule mô hình hóa; PL3 khép lại với chi
  phí benign FP đáng kể. UA/tool-detection chỉ là tín hiệu mềm.
- **ML WAF:** mạnh với family đã học (0 FP, 0 miss trên corpus trừ case
  out-of-distribution), yếu với biến thể ngoài phân phối — score 0.276 cho bypass
  thật. Cần hybrid + quy trình nạp sample mới có kiểm soát.
- **Kỹ thuật né tránh "kinh điển" (double encoding, case+comment, parsing
  discrepancy) không tạo bypass thật trên cấu hình này** — kết quả âm có giá trị:
  chúng hoặc bị chặn hoặc chỉ đạt `pass_without_effect`. Bypass thật duy nhất
  đứng ở semantic gap WAF↔DB.
- **Đóng góp phương pháp:** quy trình đo tách bạch detected / blocked /
  true_bypass / app effect, corpus hash-khóa tái lập được, phép đối chứng
  single-parameter để tách cơ chế — có thể tái sử dụng cho T01/C5.

---

### Phụ lục: chỉ mục evidence

| Nội dung | Đường dẫn |
|---|---|
| Bảng bypass rate (sản phẩm #1) | `results/tables/t03-final-synthesis-20261115.md` |
| Matrix 37-case v1.4 (hash kết quả) | `results/tables/g3-candidate-metrics-v1.4-37case-20261114.md` |
| Baseline khóa v1.1 37-case | `results/tables/g3-candidate-metrics-37case-20261113.md` |
| Cơ chế bypass + single-parameter control | `results/gates/HPP-arithmetic-bypass-20261113.md` |
| Corroboration wafw00f + sqlmap | `results/tables/tools-corroboration-20261115.md` |
| Gate chấp nhận v1.4 (A7 28/30, OOF NOT EVALUATED) | `results/gates/v1.4-acceptance-audit-20261115.md` |
| Quyết định G3 (amendment, relabel, v1.4 candidate) | `results/gates/G3-readiness-20261113.md` |
| R0–R13 / G2 sign-off | `results/gates/R13-checklist-20261112.md` |
| Thí nghiệm dataset v1.5/v1.5.1 + trial nguồn mới | `results/tables/v1.5-kaggle-full-20261114.md`, `v1.5.1-source-weighted-kaggle-20261114.md`, `dataset-source-trial-20261115.md` |
| Run evidence (local, gitignored) | `results/raw/experiments/20261114T112812Z-1f47c60b/`, `20261114T113212Z-ee819911/`, `results/raw/sqlmap/` |
