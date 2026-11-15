# Public-tool corroboration: wafw00f + sqlmap --tamper (2026-11-15)

Independent check with the tools named in the T03 assignment brief
(`wafw00f`, `sqlmap --tamper`) against the same lab the frozen 37-case
corpus was run on: ModSecurity + OWASP CRS at PL1/PL2/PL3 in front of the
vulnerable Flask/MySQL app. Model serving: `lr-tfidf-3cls-1.1` (v1.1, the
signed baseline). Raw logs: `results/raw/sqlmap/` (intentionally untracked,
like all raw evidence).

## wafw00f v2.4.2 — fingerprinting

`wafw00f -a http://127.0.0.1:8081/product?id=1` (5 requests):

- **Detects that a WAF is present**: "the server returns a different
  response code when an attack string is used. Normal response code is
  `200`, while the response code to cross-site scripting attack is `403`".
- **Does not identify ModSecurity/CRS by vendor signature** — the CRS
  container answers 403 without vendor markers (generic error page), so
  wafw00f falls back to generic detection. Finding for the report: the lab
  WAF is detectable as "a WAF" but not fingerprintable by name, which
  itself removes a recon advantage an attacker normally gets.

## sqlmap 1.10.11 — bypass matrix

Common flags for every run:
`-u <target> -p id --batch --flush-session --level=2 --risk=1
--technique=BEU --threads=4 --time-sec=1 --timeout=10 --retries=1
--random-agent --output-dir=<dir>` (except the default-UA run noted below).

| Target | CRS PL | UA | Tamper | Result | 403 count |
|---|---|---|---|---:|---:|
| app direct `:8083` (no WAF) | — | random | — | **INJECTABLE** (`id is vulnerable`) | 0 |
| `:8081` CRS | PL1 | sqlmap default | — | not injectable | 275 |
| `:8081` CRS | PL1 | random | — | **INJECTABLE** (`AND boolean-based blind`, `id is vulnerable`) | 2060 |
| `:8081` CRS | PL1 | random | space2comment | not injectable | — |
| `:8081` CRS | PL1 | random | charencode | not injectable | — |
| `:8081` CRS | PL1 | random | between | not injectable | — |
| `:8081` CRS | PL2 | random | — | not injectable | — |
| `:8081` CRS | PL2 | random | space2comment | not injectable | — |
| `:8081` CRS | PL2 | random | charencode | not injectable | — |
| `:8081` CRS | PL2 | random | between | not injectable | — |
| `:8081` CRS | PL3 | random | — | not injectable | — |
| `:8081` CRS | PL3 | random | space2comment | not injectable | — |

CRS paranoia level was switched by recreating `waf-crs` with `CRS_PL`
through Compose (same mechanism the smoke runner uses); the lab was
restored to PL1 afterwards (`BLOCKING_PARANOIA=1`, `DETECTION_PARANOIA=1`
verified in the container).

## Read-across to the corpus results

1. **Tool corroboration of the per-PL picture.** sqlmap — whose tamper
   scripts implement the published technique families the corpus covers
   (`space2comment` ≈ case-variation + SQL comment, `charencode` ≈
   double encoding) — succeeds only at PL1 and only without mutation,
   exactly matching the frozen-corpus result: PL1–PL2 expose CRS blind
   spots, PL3 closes them (at a benign-FP cost, see the 37-case matrix).
2. **The bypass that worked is not a mutation.** At PL1 the successful
   run was plain boolean-blind payloads with a normal User-Agent. The
   blocking factor for the default-UA run was CRS's tool-detection rules,
   and every tamper made sqlmap *less* likely to succeed — the mutated
   payloads trip rules the original does not. Same conclusion as the
   corpus single-parameter control: mutation/obfuscation is not the
   winning mechanism; unobfuscated semantics the CRS rules do not model
   are.
3. **Tool identity is a soft signal, not a defence.** The default UA was
   blocked but a common browser UA sailed through — consistent with
   known CRS guidance that User-Agent matching is trivially evaded.
4. **CRS paranoia-level recommendation (T03 deliverable).**
   - PL1: real bypass risk — confirmed both by the frozen corpus
     (`hpp-mal-004` arithmetic tautology) and by unmutated sqlmap
     boolean-blind. Not recommended as the only barrier.
   - PL2: stops sqlmap outright in this lab and closes the tautology
     bypass only partially (corpus: `hpp-mal-004` still passes CRS-only
     at PL2; hybrid/ML-only paths differ) — acceptable balance when
     benign false positives must stay low.
   - PL3: stops every tested sqlmap path and blocks the tautology
     bypass (403, rule `949110` et al.), at the cost of benign blocked
     rates of 1/3–3/3 per technique cell in the corpus. Recommended for
     high-security deployments with an FP-tuning pass; otherwise PL2 +
     the ML layer (hybrid) is the balanced configuration.

## Limits

- sqlmap runs are one shot per (PL, tamper) cell with default technique
  breadth (`--level=2 --risk=1`, techniques B/E/U); a deeper sweep could
  find more paths, but the goal here is corroboration, not exhaustion.
- HPP/fragmentation has no direct sqlmap tamper equivalent (HPP is a
  transport-level technique); corpus evidence for that group stands on
  the 37-case runs and the single-parameter control.
- wafw00f/sqlmap results reflect this lab's CRS container and version;
  commercial WAFs are out of T03 scope.
