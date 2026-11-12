# CRS `/comment` SQLi exclusion audit (2026-11-13)

## Scope

After the group's G2 review and sign-off, this candidate addresses false positives on the XSS demonstration endpoint. The app's `/comment` endpoint reflects `text` and does not use it in a SQL query. The CRS exception removes only rule `942131` from `ARGS:text` when `REQUEST_FILENAME` is exactly `/comment`. It leaves every other CRS rule and every other endpoint in scope. In particular, XSS rules remain enabled for `/comment`.

The rule is in `waf-crs/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf` and is mounted read-only by `docker-compose.yml`. It is a runtime target exclusion; it does not edit the CRS image or lower the paranoia level.

## Evidence

The same 36-case corpus was run at PL1, PL2, and PL3, before and after the exception:

| Path | Before run | Candidate run | Benign blocked PL1 | PL2 | PL3 | Malicious blocked PL1 | PL2 | PL3 |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| CRS direct | `20261112T163850Z-de5655c2` | `20261112T171730Z-efb04f02` | 0/15 → 0/15 | 4/15 → 1/15 | 11/15 → 10/15 | 18/21 → 18/21 | 18/21 → 18/21 | 21/21 → 21/21 |
| ML hybrid | `20261112T164025Z-397bbedb` | `20261112T171923Z-0a05d016` | 0/15 → 0/15 | 4/15 → 1/15 | 11/15 → 10/15 | 21/21 → 21/21 | 21/21 → 21/21 | 21/21 → 21/21 |

Across each before/after pair, there were zero changed WAF decisions among SQLi cases and zero changed WAF decisions among malicious XSS cases. Four XSS benign case-level decisions changed from blocked to allowed: `xss-de-ben-001` PL2, `xss-hpp-ben-001` PL2, and `xss-pd-ben-002` PL2 and PL3. No other benign decisions changed. All four experiment runs report zero true bypasses, incomplete requests, invalid controls, and execution-unverified cases.

For the sole pending browser check in the direct candidate, `xss-de-mal-001` at PL2, browser evidence confirms `blocked HTTP 403`; the candidate run's pending list is now empty. The hybrid candidate had no pending browser checks.

## Validation and limits

- `docker compose config -q` passed.
- The CRS container loaded the mounted rule file and passed its Nginx configuration check; the full stack became healthy after recreation.
- The exclusion is justified for this app's current `/comment` implementation. If the endpoint later uses `text` in SQL, this exception must be removed or re-evaluated.
- These are finite-corpus candidate results. They do not sign a later gate or establish production readiness.

## Run artifacts

- Direct candidate summary and rows: `results/raw/experiments/20261112T171730Z-efb04f02/`
- Hybrid candidate summary and rows: `results/raw/experiments/20261112T171923Z-0a05d016/`
- Browser evidence: `results/raw/browser/20261112T171730Z-efb04f02/crs_only/pl2/evidence.json`
- Before-run evidence: `results/raw/experiments/20261112T163850Z-de5655c2/` and `results/raw/experiments/20261112T164025Z-397bbedb/`
