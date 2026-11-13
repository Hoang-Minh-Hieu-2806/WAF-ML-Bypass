# R7 browser replay correction (2026-11-13)

## Finding

The original `verify_xss_execution.py --mode waf-path` replay navigated to the WAF URL with Chromium's default request headers. The experiment runner uses different headers: `Host: localhost:<published-port>`, `X-Lab-Case-ID`, `User-Agent: experiment-runner/1.0`, and `Accept: application/json`. For `xss-de-mal-001` at PL2, this changed the WAF response: runner headers returned HTTP 200; Chromium defaults returned HTTP 403. The old 403 therefore did not verify the same request as the RUN row.

The original evidence has been retained locally as `evidence.browser-default-header-replay.json`; the signed G2 ZIP was not modified.

## Correction and evidence

Commit `8e62c7e` updates the WAF-path verifier to send the runner's request method, URL, headers, and body, then load the returned response body into Playwright for the execution check.

Corrected replays at PL2 returned HTTP 200, no reflection, and no execution for:

| Run | Corrected evidence | Result row |
| --- | --- | --- |
| Pre-hardening RUN-A `20261112T163850Z-de5655c2` | `results/raw/browser/20261112T163850Z-de5655c2/crs_only/pl2/evidence.json` | `pass_without_effect`, `semantic_effect=false`, `true_bypass_xss=false` |
| Post-G2 direct candidate `20261112T171730Z-efb04f02` | `results/raw/browser/20261112T171730Z-efb04f02/crs_only/pl2/evidence.json` | `pass_without_effect`, `semantic_effect=false`, `true_bypass_xss=false` |

Both pending lists are empty. PL1 evidence already matched the runner's HTTP 200 result and showed no execution. No `execution_unverified` case remains for these runs. The corrected result is a verified no-effect outcome, not a true bypass.

## Gate impact

G2 remains recorded as signed based on the group's review. This correction supplements that historical review and should be included in the next group review. It corrects the R7 interpretation without changing the HTTP outcome, SQLi regression, or hardening before/after decisions. The final G3 checklist remains unsigned until every G3 criterion and deliverable is reviewed.
