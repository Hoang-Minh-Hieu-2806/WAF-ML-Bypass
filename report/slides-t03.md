---
marp: true
theme: default
paginate: true
size: 16:9
---

<!-- _class: lead -->

# T03 — WAF học máy và kỹ thuật né tránh
## Tái lập tấn công đối kháng

Nhóm [tên nhóm] · GVHD [tên GV] · 15/11/2026

Số liệu: v1.1 serve (G3 ký) · v1.4 candidate · corpus 37-case hash-khóa

---

# 2. Bài toán

- WAF signature (ModSecurity + CRS) và WAF ML tự train **vì sao bị vượt?**
- Tái lập 4 nhóm kỹ thuật đã công bố trong giáo trình C4:
  HPP/Fragmentation · Double encoding · Case variation + SQL comment · Parsing discrepancy
- Đo **tỉ lệ bypass theo nhóm kỹ thuật**, so sánh signature vs ML
- Ngoài phạm vi: WAF thương mại / WAF-as-a-Service production

---

# 3. Kiến trúc lab

```
Client ──▶ waf-crs (ModSecurity+CRS, :8081) ──▶ web-app (Flask+MySQL, :8083)
                    │
                    ▼ (hybrid)
             waf-ml (TF-IDF + LR 3 lớp, :8082)
```

- 3 cấu hình: **CRS-only · ML-only · Hybrid** × **PL1–PL3**
- Model nền v1.1: sklearn 1.7.1, threshold 0.5, train 426 dòng lab
- Corpus: **37 case hash-khóa** = 11 case-comment + 8 double-encoding
  + 9 HPP + 9 parsing-discrepancy (22 malicious + 15 benign mỗi PL)

---

# 4. Phương pháp: tách bạch 4 khái niệm

| Khái niệm | Ý nghĩa |
|---|---|
| `detected` | WAF/ML gán nhãn tấn công |
| `blocked` | Quyết định chặn hiệu lực trên đường đi |
| `true_bypass` | Qua WAF **và** app tạo effect quan sát được |
| `pass_without_effect` | Qua WAF nhưng **không có effect** — không tính bypass |

- RUN-A/B: 111 hàng mỗi run, `incomplete=0`, `control_invalid=0`, pending-browser = 0
- Kết quả âm được phân tích cơ chế, loại trừ `execution_unverified`

---

# 5. Kết quả chính: bypass rate theo kỹ thuật

| Kỹ thuật | CRS-only PL1/2/3 | ML-only PL1/2/3 | Hybrid PL1/2/3 |
|---|---|---|---|
| Case+comment | 0/8 · 0/8 · 0/8 | 0/8 · 0/8 · 0/8 | 0/8 · 0/8 · 0/8 |
| Double encoding | 0/5 · 0/5 · 0/5 | 0/5 · 0/5 · 0/5 | 0/5 · 0/5 · 0/5 |
| HPP | **1/5 · 1/5** · 0/5 | **1/5 · 1/5 · 1/5** | **1/5 · 1/5** · 0/5 |
| Parsing discrepancy | 0/4 · 0/4 · 0/4 | 0/4 · 0/4 · 0/4 | 0/4 · 0/4 · 0/4 |

> **Đúng 1 bypass thật: `hpp-mal-004`.** Double encoding chỉ đạt
> `pass_without_effect`. Tỉ lệ thật = 1/22 malicious case.

---

# 6. Signature vs ML trên case bypass

| | CRS | ML (v1.1) |
|---|---|---|
| `hpp-mal-004` PL1–2 | cho qua | cho qua |
| `hpp-mal-004` PL3 | **403 chặn** | cho qua |
| Attack score | (signature) | **0.276 < 0.5** |
| Benign FP trong corpus | PL1: 0/15 · PL2: 1/15 · **PL3: 10/15** | **0/15** |

- CRS blind spot ngữ nghĩa; PL3 chặn nhưng trả giá benign FP 66.7%
- ML: 0 FP nhưng blind với payload ngoài phân phối train

---

# 7. Đối chiếu công cụ công khai

**wafw00f:** phát hiện "có WAF" (200 vs 403) — **không dò được vendor**

**sqlmap 1.10.11:**

| Target | Kết quả |
|---|---|
| App trực tiếp (không WAF) | INJECTABLE |
| CRS PL1, UA sqlmap | blocked (275×403) |
| CRS PL1, UA trình duyệt | **INJECTABLE** — boolean-blind |
| CRS PL1–3 + mọi tamper | blocked — **mutation làm tệ hơn** |

Mutation không phải cơ chế thắng — CRS blind spot ngữ nghĩa mới là.

---

# 8. Cơ chế gốc (+10%): single-parameter control

Cùng payload, **không nhân đôi tham số**:

| Request | CRS PL2 | CRS PL3 | ML score |
|---|---|---|---|
| `?id=1%2B1` (đơn) | 200, row 2 | 403 | benign 0.778 / attack **0.210** |
| `?id=1%2B1&id=1` (case gốc) | 200, bypass | 403 | benign 0.724 / attack **0.266** |

**Kết luận:** nhân đôi HPP **không đổi quyết định WAF nào** →
cơ chế thật = **CRS arithmetic-tautology blind spot trên `1+1`**
Flask first-value-wins → MySQL đánh giá `WHERE id = 1+1` → row 2
Đúng loại semantic gap mà **WAFFLED (ACSAC 2025)** mô tả

---

# 9. Khuyến nghị cấu hình CRS (sản phẩm riêng #2)

| PL | Bypass CRS-only | sqlmap | Benign blocked | Khuyến nghị |
|---|---|---|---|---|
| PL1 | **Có** | Qua | 0/15 | Không dùng đơn lẻ |
| PL2 | **Có** (tautology) | Không qua | 1/15 | **Cân bằng: PL2 + hybrid ML** |
| PL3 | Không (403) | Không qua | 10/15 | Ưu tiên chặn; bắt buộc tune FP |

- FP PL3 do rule `932350` match **tên tham số** `id` → exception hẹp theo endpoint
- **Khuyến nghị lab: PL2 + hybrid**

---

# 10. Model: v1.1 ↔ v1.4 ↔ v1.5/1.5.1

| | v1.1 (serve) | v1.4 (candidate) | v1.5/1.5.1 (thí nghiệm) |
|---|---|---|---|
| Macro-F1 | 0.929 (OOF lab) | **0.996** (external 10,211) | kém hơn v1.4 |
| WAF-path corpus | baseline khóa | **0 lệch** so với v1.1 | chưa chạy đầy đủ |
| Gate | A1–A7 PASS | A7 28/30; OOF **NOT EVALUATED** | FAIL promote |

v1.4 tốt hơn rõ trên external nhưng **chưa đủ gate để promote** —
cần OOF/group + train lab-overlap-free.

---

# 11. Giới hạn (khai báo trung thực)

- 22/37 case corpus trùng exact với data train lab → một phần in-sample
- OOF/group v1.4 **NOT EVALUATED** (nguồn không có family metadata)
- Holdout XSS chỉ payload-level, safety-neutralized — chưa chứng minh executable
- sqlmap/wafw00f: 1 lần chạy mỗi cell — đối chiếu, không vét cạn
- Benign set lab nhỏ (15 dòng) — chỉ báo, không ngoại suy production

---

# 12. Kết luận

- Signature: bypass ở PL1–2 bằng **ngữ nghĩa đơn giản**, không cần obfuscation
- ML: mạnh với family đã học, **blind ngoài phân phối** → cần hybrid
- Kỹ thuật "kinh điển" (double encoding, case+comment, parsing discrepancy)
  **không tạo bypass thật** — kết quả âm có giá trị
- Đóng góp: quy trình đo tách bạch detected/blocked/bypass/effect +
  corpus hash-khóa tái lập được

---

<!-- _class: lead -->

# 13. Demo live

```
$ curl "http://127.0.0.1:8081/product?id=1%2B1&id=1"     # qua CRS PL1
HTTP 200  {"rows":[{"id":2,"username":"bob"}]}            # row 2, không phải row 1!

$ curl "http://127.0.0.1:8083/product?id=1%2B1&id=1"     # app trực tiếp
HTTP 200  {"rows":[{"id":2,"username":"bob"}]}            # app lỗ hổng thật

# CRS PL3: cùng request → HTTP 403 Forbidden              # WAF chặn
```

Bypass thật = effect quan sát được, không chỉ HTTP 200
