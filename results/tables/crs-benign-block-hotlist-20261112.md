# CRS benign-block hotlist - RUN-A (2026-11-12)

## Scope

- Primary source: RUN-A `20261112T163850Z-de5655c2`, CRS-only outcome, 36-case corpus, PL1-PL3.
- Corpus commit: `ea00b96` (`fix(dataset): align chunked form content types`).
- Counts are benign case-rounds blocked out of 15 benign cases at each PL.
- Rule frequencies count matches across blocked benign transactions; a transaction can match multiple rules.
- Rule `949110` is the anomaly scoring/block gate and is not counted as a root match.
- Raw evidence is local in ignored `results/raw/experiments/20261112T163850Z-de5655c2/`.

## Observed benign blocks and root-rule frequency

| PL | Benign blocked | Benign FPR | Root rule ID frequencies |
|---:|---:|---:|---|
| 1 | 0/15 | 0.00% | none |
| 2 | 4/15 | 26.67% | `942131`: 4; `920230`: 1; `932200`: 1; `941320`: 1 |
| 3 | 11/15 | 73.33% | `920272`: 7; `921180`: 4; `942131`: 4; `920230`: 3; `932350`: 2; `932200`: 1; `941320`: 1; `942431`: 1; `942460`: 1 |

## Representative rows to inspect

| Case | PL | Benign family / technique | Root rule IDs |
|---|---:|---|---|
| `xss-hpp-ben-001` | 2-3 | `benign.lt` / HPP | `942131` at PL2; `920272`, `921180`, `942131` at PL3 |
| `xss-de-ben-001` | 2-3 | `xss.encoding` / double encoding | `920230`, `942131` at PL2; `920230`, `920272`, `942131` at PL3 |
| `xss-pd-ben-001` | 2-3 | `benign.html` / parsing discrepancy | `932200`, `941320`, `942131` at PL2; plus `920272`, `942431`, `942460` at PL3 |
| `xss-pd-ben-002` | 2-3 | `benign.lt` / parsing discrepancy | `942131` at PL2-3 |
| `hpp-ben-001` | 3 | `benign.html` / HPP | `921180`, `932350` |
| `pd-ben-003` | 1-3 | benign form login / chunked transfer | allowed, HTTP 200, no CRS root rule after adding the form Content-Type |

The previous RUN-A had `920640` matches on `pd-ben-003` and `pd-mal-001` because both chunked form requests omitted Content-Type. Both fixtures now explicitly send `application/x-www-form-urlencoded`. In the refreshed run, `pd-ben-003` is allowed and `pd-mal-001` is blocked by SQLi rules, including `942100` at PL1. This isolates the intended chunked-transfer behavior from the missing-header protocol rule.

## Hardening decision criteria

This is a diagnosis list, not a CRS change. Before adding an exclusion, inspect the exact CRS rule configuration and matched variable, and confirm the proposed scope is narrow enough to preserve attack coverage. Record a before/after run on the same corpus at all three PLs and compare:

- benign blocked case-rounds and FPR;
- malicious detection, blocking, and true-bypass counts;
- rule IDs for every changed outcome;
- `incomplete` and `control_invalid_total` (both must remain zero).

Do not suppress `949110` as a substitute for identifying the root match. Do not disable a rule globally based only on these aggregate counts. CRS hardening starts after G2 review.
