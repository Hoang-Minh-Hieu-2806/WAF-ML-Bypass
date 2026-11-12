# CRS benign-block detail - RUN-A (2026-11-12)

## Purpose and scope

This note expands the hotlist with exact audit-log matches from RUN-A `20261112T163850Z-de5655c2`, on the 36-case corpus at PL1-PL3. The corpus correction is commit `ea00b96`. The audit identifies OWASP CRS `4.30.0` and ModSecurity `3.0.17`.

Counts below are rule matches on blocked transactions, not unique cases. Rule `949110` is omitted because it is the anomaly-score gate. The source audit is local in ignored `results/raw/experiments/20261112T163850Z-de5655c2/`.

## Benign matches and attack overlap

| Rule | CRS message in this run | Benign PL1 / PL2 / PL3 matches | Malicious PL1 / PL2 / PL3 matches | Benign evidence and attack overlap |
|---|---|---:|---:|---|
| `920640` | Content-Type header missing from request with body | 0 / 0 / 0 | 0 / 0 / 0 | The earlier chunked form fixtures omitted Content-Type. Both now send `application/x-www-form-urlencoded`; `pd-ben-003` passes, while `pd-mal-001` is caught by SQLi rules. |
| `920230` | Multiple URL Encoding Detected | 0 / 1 / 3 | 0 / 2 / 5 | `xss-de-ben-001` intentionally uses double-encoded benign markup. This is the technique under test, so record its expected CRS behavior; broad suppression weakens evasion detection. |
| `920272` | Invalid character in request (outside printable ASCII below 127) | 0 / 0 / 7 | 0 / 0 / 6 | PL3 benign values include percent-decoded Vietnamese UTF-8 text. Malicious matches also occur; any exception must be limited to correctly encoded text and tested against encoded attack cases. |
| `921180` | HTTP Parameter Pollution | 0 / 0 / 4 | 0 / 0 / 4 | Duplicate names in HPP cases trigger the rule. Decide whether duplicate parameters are legitimate for the demo application's request semantics. |
| `932200` | RCE Bypass Technique | 0 / 1 / 1 | 0 / 4 / 4 | `xss-pd-ben-001` includes harmless `<sup>` markup and Markdown. The rule also matches obfuscated attack requests. |
| `932350` | Direct Unix Command Execution (No Arguments) | 0 / 0 / 2 | 0 / 0 / 5 | PL3 matches the parameter name `id` in `ARGS_NAMES:id` on benign product requests. It also matches malicious traffic; any target exclusion needs narrow review. |
| `941320` | Possible XSS Attack Detected - HTML Tag Handler | 0 / 1 / 1 | 0 / 4 / 4 | `xss-pd-ben-001` contains harmless `<sup>` markup. The same rule matches script-bearing XSS requests. |
| `942131` | SQL Boolean-based attack detected | 0 / 4 / 4 | 0 / 3 / 3 | Benign comparison text such as `a < b` and `<sup>regulations</sup>` trigger the rule. It also matches SQLi and script-bearing XSS inputs. |
| `942431` | Restricted SQL character anomaly (args), threshold 6 | 0 / 0 / 1 | 0 / 0 / 9 | `xss-pd-ben-001` contains benign HTML/Markdown punctuation; the rule also matches numerous malicious cases. |
| `942460` | Meta-character anomaly, repetitive non-word characters | 0 / 0 / 1 | 0 / 0 / 12 | `xss-pd-ben-001` contains markup and Markdown punctuation; the rule also matches SQLi cases. |

The exact rule names, matched variables, and data come from this run's audit JSON and the corresponding rules in the pinned CRS image. Rule files can change across CRS releases; the pinned image and archived audit define the version used here. See the official CRS source files for [920 protocol enforcement](https://github.com/coreruleset/coreruleset/blob/main/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf), [921 protocol attack](https://github.com/coreruleset/coreruleset/blob/main/rules/REQUEST-921-PROTOCOL-ATTACK.conf), [932 RCE](https://github.com/coreruleset/coreruleset/blob/main/rules/REQUEST-932-APPLICATION-ATTACK-RCE.conf), [941 XSS](https://github.com/coreruleset/coreruleset/blob/main/rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf), and [942 SQLi](https://github.com/coreruleset/coreruleset/blob/main/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf).

## Recommended order for group review

1. **Confirm the chunked fixture correction.** Both form requests carry the same form Content-Type; the direct control uses Content-Length and the WAF path uses chunked transfer, as intended. The benign request is allowed with no rule match, and the malicious request is blocked by SQLi rules.
2. **Decide intended application policy for duplicate parameters.** The HPP cases intentionally repeat parameter names. If the app accepts duplicates, decide whether CRS blocking is expected security behavior or an operational false positive; do not assume `921180` is misconfigured.
3. **Treat double encoding as attack-like input.** `xss-de-ben-001` is labeled benign but exercises the double-encoding technique. Keep its label and expected outcome explicit; do not weaken `920230` globally to improve FPR.
4. **Consider international-text policy only with attack controls.** `920272` flags UTF-8 values after parsing. Any change must preserve detection for malformed and encoded payloads and be measured at all PLs.
5. **Keep HTML/Markdown rule overlaps visible.** `<sup>`, comparison operators, and formatting punctuation are legitimate for the demo comment field, but signatures overlap real XSS/SQLi/RCE strings. Do not remove `941320`, `942131`, `932200`, `942431`, or `942460` globally.

## Required evidence before a CRS change

The repository's compose header assigns CRS rule changes to Huy and says group review is required. After that review, evaluate each proposed change separately against the same corpus at PL1-PL3. Record per-case status, changed rule IDs, benign block count/FPR, malicious detection/blocking/bypass, and verify `incomplete=0` and `control_invalid_total=0`. Keep the current pinned CRS image as the baseline. No rule change is proposed by this note.
