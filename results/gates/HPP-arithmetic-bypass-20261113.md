# HPP arithmetic SQLi: confirmed lab bypass (2026-11-13)

`hpp-mal-004` was added at commit `b5769a5`. The ordered wire parameters are
`/product?id=1%2B1&id=1`. Flask takes the first `id` value, `1+1`; the vulnerable
MySQL query evaluates `WHERE id = 1+1` and returns row 2. The parameterized
reference returns row 1. The direct control and every allowed WAF path record
`semantic_effect=true` with no SQL error. This is an application effect, not
merely an HTTP 200 or a WAF allow decision.

| Path | PL1 | PL2 | PL3 |
| --- | --- | --- | --- |
| CRS-only | `true_bypass`, 200, no SQLi detection | `true_bypass`, 200, no SQLi detection | 403, blocked by `921180`, `932350`, `949110`; no app effect through CRS |
| ML-only | `true_bypass`, 200 | `true_bypass`, 200 | `true_bypass`, 200 |
| Hybrid CRS → ML | `true_bypass`, 200, ML allowed | `true_bypass`, 200, ML allowed | 403 at CRS; ML was not reached |

The v1.1 ML model classifies the concatenated value `1+1 1` as benign with
attack score `0.276002` below the `0.5` threshold. PL3's CRS block does not
establish SQLi detection: the runner reports `detected=false`, and the same
PL3 HPP subset blocks all three benign SQLi fixtures. Keep detection, blocking,
and application effect separate in the final report.

Evidence: RUN-A (CRS-only plus standalone ML)
`results/raw/experiments/20261113T102615Z-8f0c59cf/` and RUN-B (hybrid)
`results/raw/experiments/20261113T102710Z-e58e1432/`. The `results.json`,
`plN-audit.json`, `plN-app.json`, and `metadata.json` files contain the exact
case IDs and effective configurations. Both targeted runs cover nine HPP cases
at PL1–PL3 with `incomplete=0`, `control_invalid_total=0`, and no pending browser
checks. Raw evidence is intentionally ignored by Git; retain the local run
directories when sharing the report.

## Single-parameter control (2026-11-13, post-hoc) — duplication is NOT the cause

To isolate whether the repeated `id` parameter (HPP) is what defeats the WAF, the
same payload was replayed **without** parameter duplication at the standard
paranoia levels:

| Request | CRS PL2 | CRS PL3 | ML `/score` text | ML result |
| --- | --- | --- | --- | --- |
| `/product?id=1%2B1` (single) | 200, served row 2 (`rows:[{"id":2,"username":"bob"}]`) | 403 | `1+1` | benign 0.778, attack 0.210 |
| `/product?id=1%2B1&id=1` (dup, the case) | 200, `true_bypass` | 403 | `1+1 1` | benign 0.724, attack 0.266 |

Conclusions:
- The bypass outcome is **identical with and without duplication** at every PL:
  allowed at PL1–2, blocked at PL3. Duplication does not change any WAF decision.
- The DB effect is real **without** duplication too: MySQL evaluates
  `WHERE id = 1+1` and returns row 2 either way.
- Therefore the mechanism is a **CRS semantic blind spot on the arithmetic
  tautology `1+1`** (no rule matches it at PL1–2; PL3 blocks it indirectly),
  not an HPP parser discrepancy. Duplication raises the ML attack score slightly
  (0.210 → 0.266) but both stay well below the 0.5 threshold.

Classification impact: the case is a genuine WAF bypass with real application
effect, but its technique label "HPP" is misleading — the accurate description is
"arithmetic-tautology CRS blind spot (payload happens to use HPP ordering)". The
37-case corpus, its hashes, and the recorded runs are frozen; re-describing the
technique in the corpus would invalidate those hashes. The group must decide
whether to (a) relabel the technique for the report only, (b) add a true
HPP-parser-discrepancy case in a future corpus version, or (c) keep the label as
is. No corpus change is recommended before G3.

Evidence for the control: captured 2026-11-13 against the running lab
(waf-crs PL2/PL3 via `CRS_PL`, waf-ml `POST /score`, waf-app direct). The probe
used the same effective configuration as the recorded runs (model v1.1,
threshold 0.5). Raw transcripts were not persisted as run directories; treat
this section as a manual control note and keep the numbers above as the record.

This is an HPP arithmetic case, not a double-encoded SQLi case. It therefore
does not by itself satisfy the literal G3 §6.3 requirement for a double-encoded
SQLi or confirmed XSS bypass. The group/design owner must decide whether to
amend that requirement. The older 36-case candidate metrics remain a historical
snapshot and must not be presented as metrics for this 37-case corpus.
