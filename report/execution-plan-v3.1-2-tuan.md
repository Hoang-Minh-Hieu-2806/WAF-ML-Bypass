# Kế hoạch thực hiện 2 tuần — v3.1 (SQLi + XSS)

> **Cửa sổ thực hiện:** 13/11/2026 (Thứ Sáu) → 26/11/2026 (Thứ Năm) — D1→D14.
> **Nguồn thiết kế:** `report/technical-design-v3-xss.md` (v3.1) — §15 timeline,
> §14 checklist R0–R13, §9.5 tiêu chí chấp nhận A1–A7, §12.1 run matrix,
> §16 risk register. Kế hoạch này là **lập lịch thực thi**, không đổi thiết kế.
> **Ngày lập:** 12/11/2026.

---

## 0. Nguyên tắc và rào chắn (đọc đầu tiên)

1. **Nhịp 2 cột:** Tuần 1 (13–19/11) = nền tảng + số liệu; Tuần 2 (20–26/11) =
   verify + hardening + deliverables.
2. **Dependency một chiều, không vòng lặp:** X1–X4 → RUN-A/B (X5) → R7 → R13.
   R7 **không** bao giờ là điều kiện của X5 (pending list sinh từ kết quả run).
3. **Rào chắn git/docker** (không đổi so với ràng buộc dự án):
   - Không `restore/reset/checkout/switch` trên files dự án; không
     `merge/commit/push` khi chưa qua gate + duyệt chủ dự án.
   - Docker rebuild **chỉ** chạy tại gate R10 hoặc khi task ghi rõ.
   - Không sửa dataset/model ngoài quy trình §9.
4. **Evidence-first:** mọi số trong báo cáo cuối phải truy được về
   `results/` (run evidence) hoặc metrics.json — không số "từ trí nhớ".
5. **Checkpoint hằng ngày** (30 phút, cuối ngày): mỗi owner báo 3 dòng —
   *đã làm / sẽ làm / blocker*. Blocker không xử được trong 4h ⇒ bật lên
   gate review, không lặng lẽ trễ deadline.

**Ngày Chủ Nhật:** D3 (15/11) và D10 (22/11) là CN — nhóm có thể nghỉ; mọi task
trượt 1 ngày sẽ được buffer D9–D10 hấp thụ (xem §4).

---

## 1. Vai trò (không đổi theo phân công hiện có)

| Thành viên | Mảng chính | Task chính trong 2 tuần |
|---|---|---|
| **Hiếu** | Docker + web-app | B0 merge, X1 endpoint XSS, R6, CRS hardening (cùng Huy), merge dev→main |
| **Huy** | waf-crs | Conflict CRS-side, smoke payload XSS qua CRS sớm, hardening exception theo rule-id evidence |
| **Đặng Văn Hoàng (ĐVH)** | waf-ml | X4 dataset 3-class + model `lr-tfidf-3cls-1.1`, A1–A7, R8, R11/R12, Kaggle (nếu dư) |
| **Long** | Corpus | X2 10 case XSS schema v2, family taxonomy, duyệt `docs/interfaces.md`, soát control_invalid |
| **Huỳnh** | Runner + metrics | X3 runner v2, RUN-A/B, R4/R5/R11, R7 browser WAF-path, R13, bảng metrics cuối |

---

## 2. Điều kiện đầu vào — chốt trước/sau D1 (khởi động ngay tối 12/11)

| # | Việc | Người | Hạn |
|---|---|---|---|
| 0.1 | Chủ dự án quyết **Q1–Q8** (v3.1 §18) — Q1 restore `requirements-attack.txt`, Q2 merge feature/crs, Q3 fail-closed, Q4 `/score` 3-class, Q5 10 case XSS, Q6 naming, Q7 Kaggle, Q8 bỏ probe RUN-B | cả nhóm (bỏ phiếu khuyến nghị đã ghi sẵn) | trước D1 sáng |
| 0.2 | Cài thử **Playwright** host-side (lệnh kiểm khả năng — chưa xác minh từng cài) + chạy 1 trang tĩnh test headless | Huỳnh | D1 |
| 0.3 | Xác nhận máy chạy RUN đủ: compose up healthy 4 service (không rebuild nếu không cần) | Hiếu | D1 sáng |
| 0.4 | Lưu lại diff `feature/crs` (`12e597b`) ra file patch ngoài repo (B0.1) — bản sao lưu chống mất | Hiếu | D1 sáng |

---

## 3. Timeline tổng theo ngày (bảng chính)

Ký hiệu: ⏸ chờ dependency · ∥ chạy song song được · **G** = gate quyết định
"được phép đi tiếp hay không".

### Tuần 1 — nền tảng + số liệu

| Ngày | Ngày thật | Task | Owner | Depends | Evidence/gate |
|---|---|---|---|---|---|
| D1 | Thứ Sáu 13/11 | **B0.2** baseline dev nguyên trạng: R1 (unit CRS) + R2a (unit web-app cũ) + R3 (smoke PL1, đối chiếu baseline `20261025T172523Z`: detect 100%, FPR 0%) | Hiếu + Huy | Q2 duyệt | log R1/R2a/R3 |
| D1 | Thứ Sáu 13/11 | **B0.3** worktree merge `feature/crs`→`dev`: resolve 5 files conflict đã biết (`.env.example`, `README.md`, `docker-compose.yml`, `docs/architecture.md`, `docs/quickstart-lab.md`) — CRS-side do Huy review | Hiếu + Huy | B0.2 pass | worktree diff |
| D1–D2 | 13–14/11 | **B0.4/B0.5**: R9 (`test_integrated_smoke.py` — chỉ tồn tại sau merge) + R10 (compose rebuild + healthcheck 4 service) trong worktree; **G0**: merge sạch mới tiếp | Hiếu | B0.3 | log R9/R10 |
| D1–D2 ∥ | 13–14/11 | **X1** web-app: `/comment` (template cố định + raw sink) + `/comment-escaped` (`html.escape`); **cấm** `render_template_string(input)`; unit test AC-1..4 (R2b); port bind `127.0.0.1` như service hiện có | Hiếu | G0 | test log |
| D1–D2 ∥ | 13–14/11 | **X2** corpus: 10 case XSS (4 ben / 6 mal) schema v2, rải 4 folder technique hiện có; family taxonomy + README corpus; script validate schema | Long | Q5 duyệt | `corpus/**cases.json` + validate log |
| D2–D3 ∥ | 14–15/11 | **X3** runner: v2-adapter (tương thích 26 case SQLi), `rule_families` từ rule-ID thật, path allowlist + `/comment`, enforcement **P1 attack-sum** (Q8: RUN-B bỏ probe `via_ml`), output `pending_browser_verification.json` | Huỳnh | X1, X2 | runner dry-run log |
| D2–D3 ∥ | 14–15/11 | Smoke sớm CRS trên 2–3 payload XSS (không đợi RUN) — phát hiện hành vi 941xxx sớm | Huy | X2 draft | smoke note |
| D3–D4 ∥ | 15–16/11 | **X4** waf-ml: build_dataset v2 (vuln/family), train `lr-tfidf-3cls-1.1`, **StratifiedGroupKFold + 4 kiểm tra §9.4**, OOF A1–A7, export artifact **giữ v1.0 nguyên vẹn**, `fp_checks_html` ≥ 90% | ĐVH | X2 family | metrics.json |
| D4 | Thứ Hai 16/11 | Duyệt **`docs/interfaces.md` v2** (schema + `/score` 3-class) — PR review cả nhóm; chốt mọi thuật ngữ trước khi RUN | Hiếu chốt, cả nhóm | X1–X3 draft | PR approved |
| D4 | Thứ Hai 16/11 | R8: curl probe `/score` (sqli/xss/benign + benign HTML) — label đúng, `degraded:false` | ĐVH | X4 | curl log |
| D4 | Thứ Hai 16/11 | R6: app-control browser (`verify_xss_execution.py --mode app-control`) — `/comment` executed, control `not_executed` | Huỳnh | X1 | browser JSON (app_control) |
| **G1** | tối D4 (16/11) | **Gate 1:** X1+X2+X3+X4 xong; R6, R8 pass; A1–A7 đạt (hoặc rollback `ML_MODEL_DIR` về v1.0 quyết ngay tại đây) | cả nhóm | — | checklist G1 |

### Tuần 1–2 chuyển tiếp — RUN + verify

| Ngày | Ngày thật | Task | Owner | Depends | Evidence/gate |
|---|---|---|---|---|---|
| D5–D6 ⏸ | 17–18/11 | **X5 → RUN-A** (`--crs-backend direct --levels 1 2 3`) + **RUN-B** (`--crs-backend ml --levels 1 2 3`): kiểm `tx.blocking_paranoia_level` trước mỗi run (rủi ro kẹt PL3); lưu results.json/csv per run-ID | Huỳnh | **G1** | run evidence |
| D6 ∥ | 18/11 | **R4**: SQLi regression CRS-only — RUN-A subset SQLi vs `2af841ab` (block 13/13/15, FPR 9.1/9.1/72.7%, bypass 0) | Huỳnh | RUN-A | results diff |
| D6 ∥ | 18/11 | **R5**: SQLi regression hybrid — RUN-B subset SQLi vs `4e4a7f2d` | Huỳnh | RUN-B | results diff |
| D6 ∥ | 18/11 | **R11**: threshold sweep trên **attack-sum policy** (báo cả 2 cột policy); chốt threshold | ĐVH | RUN-A | sweep output |
| D6–D7 ⏸ | 18–19/11 | **R7**: WAF-path browser verification trên pending list (`--mode waf-path --config … --pl …`) — mọi (case, config, PL) được phép qua; chốt `true_bypass_xss` theo §7.3 | Huỳnh | RUN-A/B | browser JSON (waf_path) |
| D7 | Thứ Năm 19/11 | **R13**: full integration regression — R1–R12 pass, pending list **empty**, matrix 3 config × 3 PL đầy đủ, `incomplete=0`, `control_invalid_total=0` mỗi run | Huỳnh + cả nhóm | R7 | checklist R13 |
| **G2** | tối D7 (19/11) | **Gate 2:** số liệu chốt; regression SQLi sạch; hardening có evidence để dựa | cả nhóm | — | checklist G2 |

### Tuần 2 — hardening + deliverables

| Ngày | Ngày thật | Task | Owner | Depends | Evidence/gate |
|---|---|---|---|---|---|
| D7–D9 ∥ | 19–21/11 | **CRS hardening**: exception hẹp theo rule-id evidence từ RUN-A/B (xử cả 941 FP nếu có); before/after so sánh trên chính corpus | Huy + Hiếu | G2 | diff + before/after run |
| D8–D10 ∥ | 20–22/11 | **Kaggle external holdout** (Q7 — chỉ nếu buffer dư, hard cut nếu trễ) | ĐVH | X4 | holdout note |
| D8–D12 ∥ | 20–24/11 | **Bảng metrics cuối**: per-vuln × per-technique × per-config × per-PL, bypass matrix, rule hotlist, hardening recommendations — toàn bộ số từ evidence thật | Huỳnh | G2 | tables |
| D9–D10 **buffer** | 21–22/11 | Resolve regression fail / re-run / re-run WAF-path browser (CN — chỉ dùng nếu có việc) | cả nhóm | G2 | — |
| D11–D13 ∥ | 23–25/11 | **Báo cáo cuối + slide + demo**: tách bạch detection/blocking/effect; demo payload trích từ evidence; demo Playwright sống | cả nhóm | R13 | report/slide |
| D13–D14 ⏸ | 25–26/11 | Review chéo toàn bộ deliverables; **merge dev→main + tag** — chỉ sau khi mọi mục §17 v3.1 được kiểm | Hiếu (duyệt chủ dự án) | **G3** | merge commit |
| **G3** | 25/11 | **Gate cuối:** Definition of Done (§6) | cả nhóm | — | checklist |

---

## 4. Buffer policy

- **D9–D10 (21–22/11)** là buffer chính: absorb trượt từ X-phase (mỗi ngày CN
  nghỉ = 1 ngày trượt) + resolve regression fail.
- Nếu buffer **đã dùng xong mà còn fail**: cut theo thứ tự trước sau —
  (1) cut Kaggle (Q7), (2) thu hẹp CRS hardening thành khuyến nghị-only
  (không sửa CRS, chỉ report), (3) giữ nguyên RUN + R7 + R13 + báo cáo —
  **không bao giờ cut** R4/R5/R7/R13.
- Không lùi deadline D14; mọi trượt được công bố tại checkpoint hàng ngày.

---

## 5. Checklist chi tiết theo owner (điều kiện "xong" từng việc)

### Hiếu (docker / web-app)
- [ ] B0.2: log R1 + R2a + R3 trên `dev` nguyên trạng, đối chiếu R3 với baseline PL1.
- [ ] B0.3: worktree merge sạch 5 files conflict; diff được Huy review CRS-side.
- [ ] B0.4/B0.5: R9 pass, R10 4 service healthy sau rebuild.
- [ ] X1: `/comment` = f-string template cố định + sink raw (không SSTI);
      `/comment-escaped` = `html.escape`; cả hai bind `127.0.0.1`; unit test
      AC-1..4 pass; evidence JSONL có `vuln:"xss"`, `xss_reflected`,
      `rendered_snippet`.
- [ ] R6: browser app-control pass (`/comment` executed, control `not_executed`).
- [ ] CRS hardening (cùng Huy, D7–D9).
- [ ] D13–14: merge dev→main sau G3 + duyệt.

### Huy (waf-crs)
- [ ] Review conflict hunks CRS-side của merge B0.3.
- [ ] D2–3: smoke 2–3 payload XSS qua CRS-only — ghi nhận rule nào bắn (sớm,
      không chờ RUN).
- [ ] D7–D9: hardening exception theo **rule-id thật** từ evidence; before/after
      trên cùng corpus; nếu có FP 941 → giải thích + fix hoặc ghi nhận.
- [ ] Phần CRS trong báo cáo cuối (rule hotlist).

### ĐVH (waf-ml)
- [ ] X4: dataset v2 (vuln + family taxonomy); 4 kiểm tra fold §9.4 được in vào
      metrics; OOF per-class + macro-F1 + confusion 3×3 + FPR 2 hướng.
- [ ] A1–A7 đạt: macro-F1 ≥ 0.80; benign ≥ 0.85, sqli ≥ 0.75, xss ≥ 0.70;
      FPR benign→sqli ≤ 5% và benign→xss ≤ 5%; binary-slice F1 ≥ 0.85 (tham
      chiếu, không paired); SQLi regression 26 case (A6 — kiểm flip
      threshold-policy); fp_checks_html ≥ 90%.
- [ ] Artifact: **v1.0 nguyên vẹn**; v1.1 export kèm version; rollback qua
      `ML_MODEL_DIR` sẵn sàng (đã test 1 lần).
- [ ] R8 curl probe pass; R11 sweep 2 policy; R12.
- [ ] Kaggle holdout nếu dư (hard cut).

### Long (corpus)
- [ ] X2: 10 case XSS đúng schema v2 (4 ben / 6 mal), `expected_waf_outcome` +
      `expected_app_effect` độc lập WAF; rải 4 folder technique; family taxonomy
      README; script validate pass cho toàn bộ 36 case.
- [ ] D4: đồng review `interfaces.md` v2.
- [ ] D6–D7: soát `control_invalid` và pending list từ RUN — corpus-side lỗi thì
      sửa case (không sửa runner) rồi re-run đúng phần.

### Huỳnh (runner / metrics)
- [ ] X3: v2-adapter (26 case SQLi chạy không đổi); `rule_families` từ ID thật
      (không hardcode 942); P1 attack-sum trong proxy enforcement + evidence
      (`attack_score`, `threshold`, `decision`); Q8 — RUN-B **không** gửi probe
      `via_ml`; `pending_browser_verification.json` sinh từ RUN.
- [ ] `verify_xss_execution.py` 2 mode: `--mode app-control` (trước RUN) và
      `--mode waf-path --config {crs_only|ml_only|hybrid} --pl {1|2|3}` (sau RUN).
- [ ] RUN-A/B đúng matrix §12.1 (số cuối đối chiếu từ results.csv — nếu lệch
      bảng đếm, ghi vào metadata run).
- [ ] R4/R5 regression pass; R7 pending empty; R13 checklist.
- [ ] Bảng metrics cuối cho report.

---

## 6. Definition of Done (G3 — điều kiện gộp cuối)

Tương ứng §17 v3.1, kiểm mục theo mục:

1. R0–R13 pass; pending-browser list **empty**.
2. Matrix đầy đủ 3 config × 3 PL × (SQLi + XSS); `incomplete=0`;
   `control_invalid_total=0` mỗi run.
3. ≥1 case `true_bypass` SQLi (decode-double) và/hoặc ≥1 `true_bypass_xss` với
   **WAF-path evidence `executed`** của đúng (case, config, PL) — kết quả âm
   phải được phân tích cơ chế và loại trừ `execution_unverified`.
4. Bảng per-vuln × per-technique × per-config có số thật từ run.
5. Model v1.0 artifact nguyên vẹn; v1.1 đạt A1–A7 **hoặc** rollback có ghi lý do
   từng tiêu chí fail.
6. Báo cáo + slide có detection/blocking/effect tách bạch, rule hotlist,
   hardening recommendations, demo payload trích từ evidence thật.
7. Merge dev→main chỉ diễn ra sau mục 6, có duyệt chủ dự án.

---

## 7. Rủi ro chính + trigger hành động (từ §16, phiên bản rút gọn)

| Trigger | Hành động ngay |
|---|---|
| Merge B0.3 conflict phức tạp hơn hunk đã liệt kê | Dừng, gọi gate review tối D1 — không tự đoán resolve CRS-side |
| A1–A7 fail tại G1 | Rollback `ML_MODEL_DIR` → v1.0 ngay; XSS đo CRS-only; ghi "ML miss XSS" là kết quả phân tích |
| Model tăng FPR benign HTML | fp_checks_html + sweep; nếu vẫn > ngưỡng → rollback |
| ML miss XSS hoàn toàn | Không coi là thất bại — là kết quả phân tích; fallback "XSS chỉ đo CRS" |
| Playwright flaky | Tín hiệu chính = DOM/title (dialog chỉ phụ); retry ×2; nếu vẫn fail → R7 dồn buffer |
| Fold thiếu lớp | 4 kiểm tra §9.4; giảm fold 5→4→3; GroupKFold phải đánh dấu protocol riêng |
| Kẹt PL3 khi RUN | Check `tx.blocking_paranoia_level` trước từng run — bắt buộc |
| RUN số lệch bảng đếm §12.1 (probe RUN-B giữ nguyên) | Đối chiếu results.csv, chốt theo code thật, ghi lệch vào metadata |
| Kaggle trễ | Cut ngay, không negotiated |

---

## 8. Deliverables ngày cuối (26/11)

1. Báo cáo cuối (số từ evidence: 324 WAF case executions / 216 direct controls /
   ≈540 HTTP, đủ theo §12.1).
2. Slide + demo (Playwright sống, payload thật từ evidence).
3. Bypass matrix per-vuln × technique × config × PL.
4. Checklist R0–R13 + 3 gate G1–G3 đã ký.
5. Tag version trên `main` (sau merge duyệt).

*Ghi chú: file này chỉ là lập lịch — mọi quyết định thiết kế vẫn dẫn chiếu
về `technical-design-v3-xss.md` (v3.1). Không sửa thiết kế qua file này.*
