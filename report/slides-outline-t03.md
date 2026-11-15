# T03 slide outline (draft 2026-11-15)

12 slide, mỗi slide 1 thông điệp. Số trong ngoặc = nguồn evidence trong repo.

1. **Trang bìa** — T03: WAF học máy và kỹ thuật né tránh; nhóm, GV, ngày.
2. **Bài toán** — vì sao WAF (signature + ML) bị vượt; tái lập 4 nhóm kỹ thuật
   đã công bố trên lab ModSecurity + CRS + WAF ML tự train.
3. **Kiến trúc lab** — sơ đồ: client → CRS (:8081) → Flask/MySQL (:8083); ML
   (:8082); 3 cấu hình CRS-only / ML-only / hybrid; PL1–3.
4. **Phương pháp** — corpus 37-case hash-khóa × 4 kỹ thuật × PL1–3; định nghĩa
   tách bạch detected / blocked / true_bypass / app effect; `pass_without_effect`
   không tính (bảng v1.4, T03 synthesis).
5. **Kết quả chính: bảng bypass rate** — 1 ảnh bảng T03; thông điệp: đúng 1
   bypass thật (`hpp-mal-004`), các nhóm còn lại bị chặn hoặc không có effect.
6. **So sánh signature vs ML** — CRS blind spot `1+1` ở PL1–2, PL3 chặn + FP
   benign; ML attack score 0.276 < 0.5 cho payload thật (ml.json run 13/11).
7. **Corroboration công cụ** — wafw00f: có WAF, không dò tên; sqlmap: chỉ qua
   ở PL1, mutation làm tệ hơn (bảng tools-corroboration-20261115.md).
8. **Cơ chế gốc (+10%)** — single-parameter control: không HPP vẫn bypass →
   CRS arithmetic-tautology blind spot, không phải parser HPP; WAFFLED (2025)
   cùng loại semantic gap.
9. **Khuyến nghị cấu hình CRS** — PL2 + hybrid = cân bằng; PL3 = an toàn, có
   FP cost (bảng benign blocked per cell).
10. **Model: v1.1 ↔ v1.4 ↔ v1.5/1.5.1** — v1.1 serve (A1–A7 pass), v1.4
    candidate tốt hơn trên external holdout nhưng chưa đủ gate promote
    (OOF NOT EVALUATED, A7 28/30); v1.5/1.5.1 chỉ là thí nghiệm dataset.
11. **Giới hạn** — 22/37 case trùng train data; holdout payload-level; XSS
    safety-neutralized; sqlmap một lần mỗi cell.
12. **Kết luận + demo** — bypass thật cần effect quan sát được, không chỉ
    HTTP 200; segue sang demo live.

Demo (sau slide 12, hoặc slide riêng 13):
- CRS-only PL1: `GET /product?id=1%2B1&id=1` → 200, trả row 2 (bob) — bypass
  thật, effect quan sát được.
- Cùng request CRS-only PL3: 403 blocked (rule 921180/932350/949110).
- Trực tiếp app :8083: trả row 2 — chứng minh app lỗ hổng, WAF mới là chốt.
- (Tuỳ chọn) sqlmap PL1 injectable vs PL2/PL3 blocked.
