# CRS benign-block detail - RUN-A (2026-11-12)

## Purpose and scope

This note expands the RUN-A hotlist with exact audit-log matches. It is diagnosis only: it does not change CRS configuration, application behavior, or corpus cases. Source run: `20261112T151032Z-6eea4579`, CRS-only, 36 cases, PL1-PL3. The audit logs identify OWASP CRS `4.30.0` and ModSecurity `3.0.17`.

Counts below are rule matches on blocked transactions, not unique cases. `949110` is omitted because it is the anomaly-score gate. The source audit is local in ignored `results/raw/experiments/20261112T151032Z-6eea4579/`.

## Benign matches and attack overlap

| Rule | CRS message in this run | Benign PL1 / PL2 / PL3 matches | Malicious PL1 / PL2 / PL3 matches | Exact benign evidence |
|---|---|---:|---:|---|
| `920640` | Content-Type header missing from request with body | 1 / 1 / 1 | 1 / 1 / 1 | `pd-ben-003` and paired `pd-mal-001` send chunked form bodies without Content-Type. Both trigger this rule. Their direct controls use the normal sender, which adds `application/x-www-form-urlencoded`, so the direct and CRS requests are not wire-equivalent. |
| `920230` | Multiple URL Encoding Detected | 0 / 3 / 3 | 0 / 5 / 5 | `de-ben-001` uses deliberate double-encoded `<sup>` markup. This is the technique under test, so classify the case's expected CRS result explicitly; broad suppression weakens evasion detection. |
| `920272` | Invalid character in request (outside printable ASCII below 127) | 0 / 0 / 7 | 0 / 0 / 6 | Several PL3 benign requests carry percent-decoded Vietnamese UTF-8 (for example Vietnamese UTF-8 text) and are counted as rule matches. Malicious matches also occur; any exception must be limited to correctly encoded text and tested against encoded attack cases. |
| `921180` | HTTP Parameter Pollution | 0 / 0 / 4 | 0 / 0 / 4 | Duplicate names in HPP cases (`id=2&id=2`, repeated `q`/`text`) trigger the rule. This is expected from the HPP test shape; document whether duplicate parameters are legitimate for this application. |
| `932200` | RCE Bypass Technique | 0 / 1 / 1 | 0 / 4 / 4 | `pd-ben-001`: Markdown/HTML text containing `</sup> -- markdown: **bold**`; matched punctuation includes `</sup>`, an em dash, and Markdown asterisks. Same rule matches obfuscated attack requests. |
| `932350` | Direct Unix Command Execution (No Arguments) | 0 / 0 / 2 | 0 / 0 / 5 | PL3 matches the parameter name `id` in `ARGS_NAMES:id` on benign product requests (`pd-ben-002`, `hpp-ben-001`). It also matches malicious HPP attack traffic. A candidate target exclusion would need to be scoped and validated carefully. |
| `941320` | Possible XSS Attack Detected - HTML Tag Handler | 0 / 1 / 1 | 0 / 4 / 4 | `pd-ben-001`: harmless `<sup>` markup. The same rule matches script-bearing XSS attack requests. |
| `942131` | SQL Boolean-based attack detected | 0 / 4 / 4 | 0 / 3 / 3 | Benign comparison text (`a < b`) and `<sup>regulations</sup>` trigger the rule. It also matches SQLi and script-bearing XSS inputs in the attack corpus. |
| `942431` | Restricted SQL character anomaly (args), threshold 6 | 0 / 0 / 1 | 0 / 0 / 9 | `pd-ben-001` contains benign HTML/Markdown punctuation; the rule also matches numerous malicious cases. |
| `942460` | Meta-character anomaly, repetitive non-word characters | 0 / 0 / 1 | 0 / 0 / 11 | `pd-ben-001` contains `> --` and Markdown punctuation; the rule also matches SQLi cases. |

Rule names and matched variables above come from the run's audit JSON. CRS rule source files in the running image were also checked at the logged rule locations. The official CRS files describe the corresponding protocol, RCE, XSS, and SQLi rule families: [920 protocol enforcement](https://github.com/coreruleset/coreruleset/blob/main/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf), [921 protocol attack](https://github.com/coreruleset/coreruleset/blob/main/rules/REQUEST-921-PROTOCOL-ATTACK.conf), [932 RCE](https://github.com/coreruleset/coreruleset/blob/main/rules/REQUEST-932-APPLICATION-ATTACK-RCE.conf), [941 XSS](https://github.com/coreruleset/coreruleset/blob/main/rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf), and [942 SQLi](https://github.com/coreruleset/coreruleset/blob/main/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf). Rule files can change across CRS releases; the pinned image and archived audit for this experiment define the versions used here.

## Recommended order for group review

1. **Fix or explicitly classify request fixtures first.** `pd-ben-003` and `pd-mal-001` omit Content-Type on chunked form bodies, while their direct controls add `application/x-www-form-urlencoded`. That changes how Flask parses the body and makes the control requests non-equivalent at the HTTP-header level. Decide whether missing Content-Type is intentional; if not, add the same explicit form Content-Type to both chunked fixtures and rerun. Do not treat the resulting `920640` block as a CRS false positive until the wire requests are corrected or the omission is part of the experiment.
2. **Decide intended application policy for duplicate parameters.** The HPP cases intentionally repeat parameter names. If the app accepts duplicates, decide whether CRS blocking is expected security behavior or an operational false positive; do not assume `921180` is misconfigured.
3. **Treat double encoding as attack-like input.** `de-ben-001` is labeled benign but uses the double-encoding technique under evaluation. Keep its label and expected outcome explicit; do not weaken `920230` globally to improve benign FPR.
4. **Consider a narrow international-text policy only with attack controls.** `920272` flags UTF-8 values after parsing. Any change must preserve detection for malformed/encoded payloads and be measured at all PLs.
5. **Keep HTML/Markdown rule overlaps visible.** `<sup>`, comparison operators, and formatting punctuation are legitimate for the demo's comment field, but the same signatures overlap real XSS/SQLi/RCE strings. Do not remove `941320`, `942131`, `932200`, `942431`, or `942460` globally.

## Required evidence before a CRS change

The repository's compose header assigns CRS rule changes to Huy and says group review is required. After that review, evaluate each proposed change separately against the same corpus at PL1-PL3. Record per-case status, changed rule IDs, benign block count/FPR, malicious detection/blocking/bypass, and verify `incomplete=0` and `control_invalid_total=0`. Keep the current pinned CRS image as the baseline. No rule change is proposed by this note.
