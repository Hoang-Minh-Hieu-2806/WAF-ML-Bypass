# T03 final synthesis: C4/C5 requirements and evidence (2026-11-15)

Source of measurements: locked v1.4 RUN-A `20261114T112812Z-1f47c60b` (CRS-only and standalone ML) and RUN-B `20261114T113212Z-ee819911` (hybrid), 37 cases × PL1–PL3. Each technique denominator below is its malicious cases per PL: case-comment 8, double-encoding 5, HPP 5, parsing-discrepancy 4. A bypass counts only with `true_bypass=true` and application effect; allowed requests without effect are excluded.

## Confirmed true-bypass rate by technique

| Technique | CRS-only PL1/2/3 | Standalone ML PL1/2/3 | Hybrid PL1/2/3 |
|---|---|---|---|
| Case variation + SQL comment | 0/8 · 0/8 · 0/8 | 0/8 · 0/8 · 0/8 | 0/8 · 0/8 · 0/8 |
| Double encoding | 0/5 · 0/5 · 0/5 | 0/5 · 0/5 · 0/5 | 0/5 · 0/5 · 0/5 |
| HPP-labeled cases | 1/5 · 1/5 · 0/5 | 1/5 · 1/5 · 1/5 | 1/5 · 1/5 · 0/5 |
| Parsing discrepancy | 0/4 · 0/4 · 0/4 | 0/4 · 0/4 · 0/4 | 0/4 · 0/4 · 0/4 |

There is one unique confirmed bypass case, `hpp-mal-004`; repeated PL/config observations are not independent payloads. Its single-parameter control showed that duplicate-parameter handling is not causal. The demonstrated mechanism is a CRS arithmetic-tautology blind spot on `1+1`. Keep the frozen corpus label `hpp`, but describe the root cause using that precise wording. Parsing-discrepancy and double-encoding pass-throughs without application effect are `pass_without_effect`, not bypasses.

## Aggregate block and false-positive trade-off

| Path | PL1 malicious blocked | PL2 malicious blocked | PL3 malicious blocked | PL1 benign blocked | PL2 benign blocked | PL3 benign blocked |
|---|---:|---:|---:|---:|---:|---:|
| CRS-only | 18/22 (81.8%) | 18/22 (81.8%) | 22/22 (100%) | 0/15 (0%) | 1/15 (6.7%) | 10/15 (66.7%) |
| Standalone ML | 21/22 (95.5%) | 21/22 (95.5%) | 21/22 (95.5%) | 0/15 (0%) | 0/15 (0%) | 0/15 (0%) |
| Hybrid | 21/22 (95.5%) | 21/22 (95.5%) | 22/22 (100%) | 0/15 (0%) | 1/15 (6.7%) | 10/15 (66.7%) |

Recommendation from this corpus: PL1 and PL2 blocked the same 18/22 malicious rows, while PL1 blocked fewer benign rows (0/15 vs 1/15); PL1 therefore has the better measured trade-off in this matrix. PL3 blocked all 22 malicious rows but also blocked 10/15 benign rows, so do not recommend PL3 as a default from this evidence. This is an empirical recommendation for the curated corpus only; keep the project's current PL2 runtime setting unless the group approves a configuration change. These are small lab denominators, not production rates.

## Tool use audit

The locked experiment records show custom corpus/runner execution. Repository search of experiment, verification, and browser raw evidence found no command log or run artifact proving execution of WAF-A-MoLE, `sqlmap --tamper`, or `wafw00f`. Their presence in `requirements-attack.txt`, README, or references is not evidence they were used. Report them as **not evidenced as used in the final runs**; do not claim their generated outputs contributed to the measurements. If the group has external terminal logs, attach them with timestamp, command, target limited to the local lab, and resulting artifact hashes before changing this statement.

## T03 alignment summary

- ModSecurity + OWASP CRS and a locally trained ML WAF were evaluated in isolated lab paths.
- The four C4 technique groups were measured across CRS-only, standalone ML, and hybrid at PL1–PL3.
- The project demonstrated a real WAF bypass, but its verified cause is arithmetic-tautology detection weakness, not a parser mismatch. No true bypass was confirmed for the parsing-discrepancy cases in this corpus.
- The project explains the distinction between WAF pass-through and application effect and has evidence linking WAF decisions to application outcomes.
- Scope stayed within the team's local Docker lab; no production WAF/WAF-as-a-Service was targeted.
- Cite the v1.4 matrix and HPP single-parameter control. Do not generalize the small curated corpus rates to real traffic.
