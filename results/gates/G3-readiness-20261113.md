# G3 readiness audit (2026-11-13)

**Status: SIGNED (owner decision, 2026-11-15 — see decision record at the end of this file).** This audit applies the G3 Definition of Done in `report/execution-plan-v3.1-2-tuan.md` §6. G2 remains signed as recorded in `R13-checklist-20261112.md`; the R7 replay correction and [HPP arithmetic bypass](HPP-arithmetic-bypass-20261113.md) are post-sign-off addenda resolved by the 15/11 decision record. Remaining before `dev`→`main` merge: final report, slides and demo.

**Addendum (2026-11-13, evening):** official 37-case runs are recorded and hash-locked in [run-audit-37case](run-audit-37case-20261113.md) — RUN-A `20261113T105850Z-f4deea31` (direct) and RUN-B `20261113T110057Z-5a65730f` (hybrid); 111 rows each, incomplete/control-invalid/pending all zero; 108 legacy case-rounds identical to the post-G2 36-case candidates. Model v1.1 is now protected against silent retrain (`ML_FORCE_TRAIN` guard, commit `e6509f2`); the rebuilt image re-ran 12 tests OK with unchanged artifact hashes. The 37-case metrics table is [g3-candidate-metrics-37case](../tables/g3-candidate-metrics-37case-20261113.md).

| G3 criterion | Status | Evidence / remaining work |
| --- | --- | --- |
| R0–R13 pass; pending lists empty | PASS with R7 addendum | R13 checklist records R0–R13. Pending lists for the signed baseline runs and post-G2 A/B candidates are empty. Corrected exact-header R7 replay is in [R7 correction](R7-replay-correction-20261113.md). Include the correction in group review. |
| 3 configs × 3 PL × SQLi/XSS; incomplete and control-invalid are zero | PASS for recorded runs | The 36-case RUN-A and RUN-B evidence covers PL1–PL3; RUN-A contains CRS-only and ML-only, RUN-B contains hybrid. The post-G2 hardening candidates are `20261112T171730Z-efb04f02` and `20261112T171923Z-0a05d016`. |
| At least one confirmed SQLi/XSS true bypass with exact WAF-path execution evidence, or analyzed negative result | HPP positive confirmed; literal G3 §6.3 still unresolved | The earlier 36-case candidates had zero true bypasses. New `hpp-mal-004` has WAF-path SQLi effect at PL1–2 on CRS-only and hybrid, and at PL1–3 on ML-only; see the [HPP addendum](HPP-arithmetic-bypass-20261113.md). G3 §6.3 specifically names double-encoded SQLi or confirmed XSS, so this HPP result does not satisfy its wording without a group/design-owner amendment. |
| Per-vulnerability × technique × config tables and bypass matrix | Candidate tables prepared; 37-case refresh pending | [Candidate metrics](../tables/g3-candidate-metrics-20261113.md) covers the earlier 36-case post-G2 runs. The targeted HPP addendum covers the new case only. Refresh the full matrix for the 37-case corpus before using it in the final report, and retain the [hardening audit](../tables/crs-comment-exclusion-audit-20261113.md) as a before/after comparison. |
| Model integrity and acceptance | PASS for recorded model criteria | v1.0 remains present with SHA-256 `model.joblib` `c469f04f0fcdba56ca1c71cb4e3ef9908457269f474e21ef452a9bf9fda6dfbb` and `metrics.json` `9ec0ea6d3799dae4fa53c7437d8dff45850da40ba5753dd220dc5378a5517f4d`. v1.1 metrics show A1–A5 and A7 pass, HTML checks 30/30; end-to-end SQLi comparison is 78/78 outcomes for both direct and hybrid. |
| Final report, slides, live demo, evidence-derived payload | NOT DONE | Prepare the report and slides with detection, blocking, and application effect kept separate; select demo payloads only from recorded evidence; rehearse Playwright live demo. |
| Group G3 review, approval, merge `dev` → `main`, and tag | NOT DONE / DO NOT MERGE | Requires completion and group review of all preceding deliverables, including the R7 correction and the unresolved literal bypass criterion. |

## Verified negative-result analysis

- CRS-only allows `de-mal-002` and `de-mal-003` at PL1 and PL2, but the corpus encodes the SQLi syntax more times than the Flask request parser decodes. The app's search query therefore receives literal percent-encoded text; the recorded application effect is false. These are `pass_without_effect`, not SQLi bypasses.
- CRS-only allows `xss-de-mal-001` at PL1 and PL2. The app receives percent-encoded markup literally; corrected PL2 browser evidence confirms no reflection and no execution. These rows are `pass_without_effect`, not XSS bypasses.
- The candidate hybrid path blocks all malicious SQLi and XSS case-rounds. Across the post-G2 candidate summaries, `true_bypasses=0`, `execution_unverified=0`, `incomplete=0`, and `control_invalid_total=0`.
- The later targeted HPP run confirms a different, arithmetic SQLi bypass. It supersedes the prior zero-bypass statement only for the expanded 37-case corpus; it does not change the recorded outcomes of the earlier candidates.

## Addendum (2026-11-14): combined-training candidate v1.3

The v1.3 candidate combines the mapped HttpParamsDataset training split with the unchanged 427-row lab dataset. Its evaluation protocol, dedup counts, source/artifact hashes, external holdout metrics, and 37-case integration evidence are recorded in [the v1.3 results table](../tables/v1.3-combined-httpparams-lab-20261114.md). Final RUN-A `20261114T051016Z-4b409c79` and RUN-B `20261114T051806Z-f6f69f39` each completed 111 rows with no pending browser checks, incomplete rows, or control-invalid rows, using source commit `89b0d5b`.

Compared with locked v1.1, v1.3 introduced no new per-case CRS/standalone-ML miss or false positive in RUN-A, and RUN-B hybrid decisions and final HTTP/effect outcomes match across all 111 rows. The six v1.2 malicious pass-throughs and one benign false positive are resolved back to v1.1 behavior. These six pass-throughs had no demonstrated application/browser effect in v1.2. `hpp-mal-004` remains a true ML-only bypass (PL1–PL3); hybrid reaches it at PL1–PL2 and CRS blocks it at PL3. The candidate was not promoted; the shared service was restored to v1.1 with CRS PL2. The pre-existing G3 positive-bypass wording question and report/demo/review work remain open, so this addendum does not change the **NOT READY / not signed** status.

## Addendum (2026-11-14): XSS-data candidate v1.4

The v1.4 candidate adds a bounded sample from Mendeley XSS dataset v2 to the unchanged v1.3 training sources. Dataset quality notes, sampling/dedup protocol, hashes, external metrics, and full 37-case comparisons are recorded in [the v1.4 results table](../tables/v1.4-xss-augmentation-20261114.md). RUN-A `20261114T112812Z-1f47c60b` and RUN-B `20261114T113212Z-ee819911` completed 111 rows each; browser pending, incomplete, and control-invalid counts are zero. The HttpParams holdout XSS recall rose from 172/177 to 173/177, and the new neutralized-payload holdout scored 4,969/5,000 XSS recall with 1/5,000 benign false positives.

On the unchanged lab corpus, RUN-A had no new standalone-ML block-decision change versus v1.3 and no CRS/application-effect outcome change versus locked v1.1; three `pd-mal-003` class labels changed to benign while the attack score still blocked all three requests. RUN-B hybrid decisions and final effects match v1.1 and v1.3. `hpp-mal-004` remains a true standalone-ML bypass at every PL and a hybrid bypass at PL1–PL2. The dataset is safety-neutralized and lacks family/source metadata, so its strong payload-holdout score does not establish executable-XSS detection or satisfy the open G3 §6.3 wording. v1.4 is not promoted; the shared service is restored to v1.1 with CRS PL2. G3 remains **NOT READY / not signed**.

## Approval boundary

This is a technical readiness audit, not a G3 signature. Do not merge `dev` to `main` or tag a release from this checklist. The group must review the R7 correction, final tables/report/demo, and decide how to resolve the explicit G3 positive-bypass requirement against the measured negative result.

## Addendum (2026-11-14): proposed §6.3 amendment + hpp-mal-004 verification

The project owner proposed amending the G3 positive-bypass criterion (§6 item 3 of `report/execution-plan-v3.1-2-tuan.md`, mirrored in §17 item 3 of `report/technical-design-v3-xss.md`): a true bypass counts when it belongs to any technique in the experimental scope (including Double Encoding or HPP) and has full WAF-path evidence — payload passes the WAF unblocked, the application produces an observable and verifiable attack effect, and the evidence links request → WAF response → application result. `pass_without_effect` cases never count. The wording is recorded in both documents and was approved by the project owner on 2026-11-15 (see decision record below).

Verification of `hpp-mal-004` against the three amended conditions, from the recorded evidence ([HPP-arithmetic-bypass](HPP-arithmetic-bypass-20261113.md), runs `20261113T102615Z-8f0c59cf` and `20261113T102710Z-e58e1432`):

1. **Passes WAF unblocked** — CRS-only and hybrid allow it at PL1–PL2, ML-only at PL1–PL3, with `detected=false` on every allowed path.
2. **Observable application effect** — `semantic_effect=true` on every allowed path: MySQL evaluates `WHERE id = 1+1` and returns row 2 instead of the reference row 1, with no SQL error.
3. **Linked evidence** — results.json, per-PL audit JSON, app JSON and metadata per run ID, joined by correlation ID.

All three conditions are met per recorded evidence; under the amended wording the case qualifies. Honesty note for the report: the single-parameter control (same file) proves the mechanism is the CRS arithmetic-tautology blind spot on `1+1`, not HPP parameter duplication — the technique label in the frozen corpus stays `hpp` (hashes locked), so the report must describe the cause accurately (decided option (a) relabel-for-report, see decision record below).

## G3 decision record (2026-11-15)

Recorded at the project owner's explicit request. Per-decision outcome:

1. **§6.3 amendment: APPROVED (option (a))** — the positive-bypass criterion is amended as written in both plan documents; `hpp-mal-004` counts as the G3 true-bypass case (verified against runs `20261113T102615Z-8f0c59cf` / `20261113T102710Z-e58e1432` and reproduced unchanged in the [v1.4 37-case matrix](../tables/g3-candidate-metrics-v1.4-37case-20261114.md)).
2. **Technique description: option (a)** — the report describes the mechanism as a CRS arithmetic-tautology blind spot on `1+1` (the payload happens to use HPP ordering). Corpus labels and hashes stay frozen; no corpus change.
3. **Model status: `lr-tfidf-3cls-1.4` remains a candidate** — promotion decision deferred until its acceptance gates (HTML benign FP 30/30, OOF/group metrics) are run for the v1.4 artifact. The served model stays `lr-tfidf-3cls-1.1`. v1.5/v1.5.1 remain experimental references only.

Honesty note: individual group-reviewer signatures were not collected; the decision was made and confirmed directly by the project owner on 2026-11-15 (same recording convention as the G2 sign-off, which was also recorded at the owner's explicit request). Gate outcome under the amended criterion: **positive-bypass requirement MET** (`hpp-mal-004`). Remaining for full G3 closure: final report, slides and demo; `dev`→`main` merge and release stay blocked until those are complete.
