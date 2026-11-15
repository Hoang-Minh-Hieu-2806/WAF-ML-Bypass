# T03 final report skeleton — WAF học máy và kỹ thuật né tránh (draft 2026-11-15)

Khung theo đúng spec T03 (C4/C5). Mỗi mục đã dẫn sẵn bằng chứng trong repo —
viết full chỉ cần khai triển các mục này. Số liệu dùng: v1.1 serve (baseline
G3 ký), v1.4 candidate, v1.5/v1.5.1 chỉ là thí nghiệm so sánh.

## 1. Mục tiêu và phạm vi
- Mục tiêu theo đề bài: hiểu vì sao WAF signature và ML bị vượt; tái lập 4 nhóm
  kỹ thuật né tránh đã công bố trên WAF mã nguồn mở.
- Ngoài phạm vi (ghi rõ): WAF thương mại / WAF-as-a-Service production.
- Refs: Demetrio 2020 (WAF-A-MoLE), Qu 2024 (AdvSQLi), Wu 2025 (WAFBooster),
  Applebaum 2021 (survey), Dawadi 2023 (DL WAF), Akhavani 2025 (WAFFLED).

## 2. Lab setup
- Docker Compose: `db` (MySQL 8.4) → `web-app` (Flask/PyMySQL, có lỗ hổng SQLi
  và XSS có chủ đích) → `waf-crs` (ModSecurity + OWASP CRS, PL1–3) và `waf-ml`
  (TF-IDF + LogisticRegression 3 lớp, threshold 0.5) → cấu hình CRS-only /
  ML-only / hybrid.
- Ports: app trực tiếp :8083, qua CRS :8081, ML :8082 (`.env`).
- Model nền: `lr-tfidf-3cls-1.1` — sklearn 1.7.1, threshold 0.5, train trên
  426 dòng lab (benign 223 / sqli 146 / xss 57, 22 families).
- Corpus kiểm thử: 37 case đóng băng (11 case-comment, 8 double-encoding,
  9 HPP, 9 parsing-discrepancy), hash khóa, `hpp-mal-004` thêm ở commit
  `b5769a5`. Chỉ dùng test, không train. 22/37 case trùng data train lab
  → ghi vào giới hạn.

## 3. Phương pháp đo
- RUN-A (CRS-only + standalone ML) và RUN-B (hybrid), mỗi run 111 hàng =
  37 case × PL1–3; `incomplete=0`, `control_invalid_total=0`, pending
  browser = 0.
- Định nghĩa tách bạch (quan trọng khi chấm): `detected` ≠ `blocked` ≠
  `true_bypass` ≠ app effect (`semantic_effect`). `pass_without_effect`
  không tính bypass.
- Kết quả âm vẫn được phân tích cơ chế, loại trừ `execution_unverified`.

## 4. Kết quả: bảng bypass rate theo kỹ thuật (sản phẩm riêng #1)
- Bảng chính: `results/tables/t03-final-synthesis-20261115.md` (theo kỹ thuật
  × config × PL) và `results/tables/g3-candidate-metrics-v1.4-37case-20261114.md`
  (chi tiết per-vuln).
- Kết quả cốt lõi: đúng 1 bypass thật duy nhất `hpp-mal-004` (CRS-only/hybrid
  PL1–2, ML-only PL1–3); double-encoding chỉ đạt `pass_without_effect`.

## 5. So sánh signature vs ML
- CRS signature: blind spot ngữ nghĩa (`1+1` tautology) ở PL1–2; PL3 chặn được
  nhưng trả giá benign FP (1/3–3/3 benign blocked mỗi cell).
- ML (v1.1): chặn tốt các family có trong tập train; với `hpp-mal-004` attack
  score 0.276 < 0.5 → cho qua (generalization chưa đảm bảo).
- Hybrid: CRS chặn trước hoặc ML chặn sau; PL3 CRS chặn, ML không được nhìn.
- Model candidate v1.4: metrics external tốt hơn rõ (macro-F1 0.996 trên
  10,211 dòng HttpParams holdout) và 0 lệch quyết định WAF-path so với v1.1
  trên corpus đóng băng; chưa promote vì A1–A5 OOF NOT EVALUATED, A7 = 28/30
  (2 FP: `<code>SELECT`, `data-id='42'`) — v1.5/v1.5.1 chỉ là thí nghiệm so
  sánh dataset, kém hơn v1.4.

## 6. Corroboration bằng công cụ công khai
- `results/tables/tools-corroboration-20261115.md`: wafw00f phát hiện "có
  WAF" nhưng không dò được vendor; sqlmap chỉ injectable ở PL1 (UA thường,
  không mutation), mọi tamper đều tệ hơn — khớp corpus: mutation không phải
  cơ chế thắng, CRS blind spot ngữ nghĩa mới là.

## 7. Khuyến nghị cấu hình CRS (sản phẩm riêng #2)
- PL1: chỉ dùng khi chấp nhận rủi ro — cả corpus lẫn sqlmap đều bypass được.
- PL2: cân bằng — chặn sqlmap, giữ benign FP thấp; nhưng tautology bypass
  vẫn qua CRS-only ở PL2 → cần lớp ML/hybrid.
- PL3: an toàn nhất — chặn toàn bộ, đổi lại phải tune FP.
- Khuyến nghị cuối: **PL2 + hybrid (ML)** làm cấu hình cân bằng của lab;
  PL3 cho môi trường ưu tiên chặn.

## 8. Cơ chế gốc của bypass (+10%)
- `hpp-mal-004`: single-parameter control chứng minh duplication KHÔNG phải
  nguyên nhân — payload không HPP cũng qua và cũng có effect. Cơ chế thật:
  CRS không có rule mô hình hóa `1+1` (arithmetic tautology) ở PL1–2; PL3
  chặn gián tiếp qua rule tổng. App (Flask first-value-wins + MySQL đánh
  giá `WHERE id = 1+1`) thực thi được → bypass thật.
- Liên hệ tài liệu: đúng loại parsing/semantic gap mà WAFFLED (ACSAC 2025)
  mô tả — WAF và app hiểu payload khác nhau.
- Nhãn corpus giữ `hpp` (hash khóa); report mô tả đúng cơ chế (quyết định
  G3 15/11, option (a)).

## 9. Giới hạn
- Corpus lab 37 case tự dựng; 22/37 trùng data train lab → không chứng minh
  generalization độc lập cho v1.4.
- Mendeley/HttpParams không có family metadata → không dựng được
  family-disjoint OOF; holdout chỉ payload-level.
- Payload XSS safety-neutralized, chưa chứng minh thực thi được trong browser
  cho source ngoài (browser evidence chỉ có cho corpus lab).
- sqlmap/wafw00f: một lần chạy mỗi cell (corroboration, không vét cạn);
  HPP không có tamper tương đương trong sqlmap.

## 10. Kết luận
- Signature WAF: bypass được ở PL1–2 bằng ngữ nghĩa đơn giản, không cần
  obfuscation; PL3 khép lại với chi phí FP.
- ML WAF: mạnh với family đã học, yếu với biến thể ngoài phân phối — cần
  hybrid + quy trình nạp sample mới.
- Đóng góp: quy trình đo tách bạch detected/blocked/bypass/effect + corpus
  hash-khóa tái lập được.
