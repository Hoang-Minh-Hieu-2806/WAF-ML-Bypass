# G1 — Chữ ký cổng chuyển pha (Có điều kiện)

- Thời điểm: 2026-11-12T15:15Z (22:15 UTC+7)
- Người ký: Hieu (assistant lane), Codex xác nhận X4 bằng commits `045f3d5` + `b87df90`
- Phạm vi: cho phép bắt đầu X5 (RUN-A/RUN-B) với **ML v1.1 `lr-tfidf-3cls-1.1` là candidate**;
  v1.1 chỉ được dùng kết quả nếu A6 per-case PASS ở RUN-A và RUN-B, ngược lại rollback v1.0.

## Evidence tối thiểu đã verify

| Mục | Kết quả | Bằng chứng |
| --- | --- | --- |
| R10 | 4/4 service healthy (`waf-app`, `waf-crs`, `waf-db`, `waf-ml`) sau rebuild | `docker compose ps` 22:05 |
| A1 | macro-F1 = 0.9289 | `waf-ml/artifacts/v1.1/metrics.json` |
| A2 | per-class F1 benign 0.9397 / sqli 0.9329 / xss 0.9143 | metrics.json v1.1 |
| A3 | benign FPR blocking = 2.24% (chỉ bằng giữ-ngoài, không vượt) | metrics.json v1.1 |
| A4 | tương quan cross = 0 | metrics.json v1.1 |
| A5 | binary-F1 = 0.9278 (v1.0 ref 0.9076) + fp_checks 30/30 | metrics.json v1.1 |
| A7 | 30/30 sanity checks pass | metrics.json v1.1 |
| R6 | oracle browser 8/8 đúng design §7.2, pending=0 | `results/raw/browser/app-control/` (lượt cuối 14:05) |
| R8 | 8/8 PASS, 0 skip, model thật (score biến đổi liên tục, `degraded=false`, `contract=v1.1-3class`) | `scripts/probe_ml_score.py` 22:05 |
| Smoke R3 PL1 | per-case **0 outcome diffs** so với baseline `20261025T172523Z-cecdfdeb` và `20261112T124455Z-5bdc229c`; ML probe TP 15/15, FP 0 | `results/raw/experiments/20261112T150608Z-b3c97c94/` |
| A6 | **Deferred** sang RUN-A/RUN-B (so per-case với baseline v1.0, flip chỉ hợp lệ khi giải thích được bằng threshold policy) | `scripts/compare_a6_baseline.py` (self-test PASS) |

## Ghi chú

- Baseline "100% detect PL1" trước đó là smoke 6-row subset (corpus cũ); aggregate giữa
  corpus cũ/mới không so sánh được — chỉ so per-case (case_id, PL). Đã xác nhận khớp 100%.
- Smoke PL1 full: SQLi CRS detect 73.33% / block 86.67% / FPR 9.09%; ML layer block 100%, FPR 0%.
- 2 bản vá khẩn cấp trước khi ký: `f851e11` (ensure_model nạp artifact bake + COPY corpus/test_train vào image —
  container từng boot-stub rồi crash) + runner resolve artifact path động (`/app/artifacts/v1.1/`).
- ML integrity: sha256 v1.1 model.joblib/metrics.json được ghi vào `runtime.ml_artifact_sha256` mỗi run.

## Addendum 2026-11-12T16:05Z — điều kiện A6 đã giải quyết: PASS cả hai lượt

| Run | ID | So với baseline v1.0 | Kết quả |
| --- | --- | --- | --- |
| RUN-A (direct) | `20261112T151032Z-6eea4579` | `20261026T135349Z-47a09e39` | 45/45 same, 0 flips → **A6 PASS** |
| RUN-B (hybrid) | `20261112T151139Z-53d2f02f` | `20261026T100617Z-4e4a7f2d` | 45/45 same, 0 flips → **A6 PASS** |

- RUN-A: CRS SQLi 73.33/86.67/9.09 (PL1) → 100%/72.73% FPR (PL3, đúng pattern baseline);
  ML layer TP 21/21 (15 SQLi + 6 XSS), FP 0, FPR 0% tại cả 3 PL; 2 case pending browser
  đã verify (PL1 not_executed / PL2 blocked 403) — `results/raw/browser/20261112T151032Z-6eea4579/`.
- RUN-B: hybrid block 100% mọi PL, bypass 0; `hybrid_ml_evidence` 33 rows, model thật
  `lr-tfidf-3cls-1.1` với `scores`/`attack_score`/`degraded` (P1 fields đầy đủ).
- R13 sweep (RUN-A, 21 mal + 15 benign): **P1 F1 100% / FPR 0% tại threshold 0.40–0.70**
  (0.50 đang dùng = tối ưu); **P2 100/100/0 mọi threshold**.
- **Kết luận: v1.1 `lr-tfidf-3cls-1.1` được thăng cấp candidate → model serving chính thức.**

## Audit correction 2026-11-12 — A6 coverage and R11 wording

The `45/45` counts in the addendum above counted only the 15 malicious SQLi cases at three paranoia levels. The earlier comparator omitted the 11 benign SQLi controls. After correcting the comparator to cover the complete 26-case SQLi corpus, including benign controls, the results are:

| Comparison | SQLi case IDs | Benign label-rounds | Malicious label-rounds | Same outcomes | Flips |
| --- | ---: | ---: | ---: | ---: | ---: |
| RUN-A vs `20261026T135349Z-47a09e39` | 26 | 33 | 45 | 78/78 | 0 |
| RUN-B vs `20261026T100617Z-4e4a7f2d` | 26 | 33 | 45 | 78/78 | 0 |

This correction supersedes the earlier `45/45` coverage figures. The full comparisons include all three PLs, and both runs have 26 matching case IDs. RUN-A's separate R4 CRS-only comparison against `20261026T100537Z-2af841ab` also matches 78/78 outcomes.

The threshold result described above is R11, not R13. The reproduced RUN-A sweep gives the same 100% F1 and 0% FPR at each tested threshold from 0.40 through 0.70 for both P1 and P2. This evidence supports retaining 0.50 as the current policy, but does not show that it is uniquely optimal. See `results/tables/r11-threshold-sweep-20261112.md`.
