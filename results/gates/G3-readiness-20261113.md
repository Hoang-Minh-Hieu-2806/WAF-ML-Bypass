# G3 readiness audit (2026-11-13)

**Status: NOT READY; G3 is not signed.** This audit applies the G3 Definition of Done in `report/execution-plan-v3.1-2-tuan.md` §6. G2 remains signed as recorded in `R13-checklist-20261112.md`; the R7 replay correction and [HPP arithmetic bypass](HPP-arithmetic-bypass-20261113.md) are post-sign-off addenda for the next group review.

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

## Approval boundary

This is a technical readiness audit, not a G3 signature. Do not merge `dev` to `main` or tag a release from this checklist. The group must review the R7 correction, final tables/report/demo, and decide how to resolve the explicit G3 positive-bypass requirement against the measured negative result.
