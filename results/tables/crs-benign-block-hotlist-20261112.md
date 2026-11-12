# CRS benign-block hotlist — RUN-A (2026-11-12)

## Scope

- Primary source: RUN-A `20261112T151032Z-6eea4579`, CRS-only outcome, 36-case corpus, PL1–PL3.
- Counts are benign case-rounds blocked out of 15 benign cases at each PL.
- Rule frequencies below count matching root rules across blocked benign case-rounds. A case can match multiple rules, so frequencies do not sum to the number of blocked cases.
- Rule `949110` is the anomaly scoring/block gate. It accompanies blocked transactions but is not counted as the root match that caused the benign false positive.
- The raw experiment and audit files are local under ignored `results/raw/experiments/`.

## Observed benign blocks and root-rule frequency

| PL | Benign blocked | Benign FPR | Root rule ID frequencies |
|---:|---:|---:|---|
| 1 | 1/15 | 6.67% | `920640`: 1 |
| 2 | 5/15 | 33.33% | `942131`: 4; `920230`: 1; `920640`: 1; `932200`: 1; `941320`: 1 |
| 3 | 12/15 | 80.00% | `920272`: 7; `921180`: 4; `942131`: 4; `920230`: 3; `932350`: 2; `920640`: 1; `932200`: 1; `941320`: 1; `942431`: 1; `942460`: 1 |

## Representative rows to inspect

| Case | PL | Benign family / technique | Root rule IDs |
|---|---:|---|---|
| `pd-ben-003` | 1–3 | `benign.html` / parsing-discrepancy | `920640` |
| `xss-hpp-ben-001` | 2–3 | `benign.lt` / HPP | `942131` at PL2; `920272`, `921180`, `942131` at PL3 |
| `xss-de-ben-001` | 2–3 | `xss.encoding` / double-encoding | `920230`, `942131` at PL2; `920230`, `920272`, `942131` at PL3 |
| `xss-pd-ben-001` | 2–3 | `benign.html` / parsing-discrepancy | `932200`, `941320`, `942131` at PL2; plus `920272`, `942431`, `942460` at PL3 |
| `hpp-ben-001` | 3 | `benign.html` / HPP | `921180`, `932350` |

Audit messages show distinct benign matches: `942131` matched comparison text such as `a < b`; `941320` matched a harmless `<sup>` tag; `932200` matched markdown punctuation; and protocol rules matched duplicate parameter names or request parsing. These are candidate false-positive mechanisms, not yet approved CRS exceptions.

## Hardening decision criteria

This is a diagnosis list, not a CRS change. Before adding an exclusion, inspect the exact CRS rule configuration and matched variable, and confirm the proposed scope is narrow enough to preserve attack coverage. Record a before/after run on the same corpus at all three PLs and compare:

- benign blocked case-rounds and FPR;
- malicious detection, blocking, and true-bypass counts;
- rule IDs for every changed outcome;
- `incomplete` and `control_invalid_total` (both must remain zero).

Do not suppress `949110` as a substitute for identifying the root match. Do not disable a rule globally based only on these aggregate counts. CRS hardening starts after G2 review.
