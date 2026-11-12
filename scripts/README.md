# scripts/ — Tự động hóa & Đánh giá (owner: Huỳnh Như Hoàng)

Giao thức và schema đã chốt tại [docs/interfaces.md](../docs/interfaces.md) (Hiếu chốt interface,
Hoàng implement). Thay đổi contract phải qua review nhóm.

## Nội dung hiện có

- `run_experiment.py` — đọc `dataset/bypass/<technique>/*.json`
  (schema mục 1 của interfaces.md, `params`/`form` là danh sách cặp có thứ tự),
  gửi y nguyên request qua CRS (`127.0.0.1:8081`), direct control (`127.0.0.1:8080`),
  và ML enforcement (`127.0.0.1:8082`); ghi `results/raw/experiments/<run-id>/`
  gồm quyết định/block/bypass/FPR riêng cho CRS và ML, app behavior, rule ID,
  model score/version, latency và evidence JSON/CSV.
- `requirements-attack.txt` — dependency tool tấn công (sqlmap, WAF-A-MoLE), cài cục bộ,
  KHÔNG đưa vào image compose.
- `sweep_thresholds.py` — đọc một `results.json`, deduplicate theo case ID và
  in bảng precision/recall/F1/FPR theo threshold mà không sửa raw evidence.

## XSS v2 runner and browser verification

`run_experiment.py` accepts both the 26 legacy SQLi v1 fixtures and the 10 XSS
v2 fixtures. v2 rows keep `vuln`, `family`, `expected_waf_outcome`, and
`expected_app_effect` separate; raw ordered parameter pairs remain intact.
SQLi uses the existing semantic-effect oracle. XSS reports an HTTP reflection
oracle separately from browser execution, which stays `execution_unverified`
until Playwright verifies that exact case/configuration/PL. Pending WAF-path
checks are written to each run's `pending_browser_verification.json` and are
excluded from confirmed-bypass metrics.

The ML-only probe runs alongside CRS in RUN-A (`--crs-backend direct`). RUN-B
(`--crs-backend ml`) records only the hybrid CRS-to-ML chain, avoiding a
duplicate standalone ML probe.

Install the optional host-side browser dependency and Chromium:

```powershell
python -m pip install -r scripts/requirements-browser.txt
python -m playwright install chromium
```

Run the app-control gate before experiments:

```powershell
python scripts/verify_xss_execution.py --mode app-control
```

After a RUN-A or RUN-B, verify only the pending cases for the selected path and
paranoia level:

```powershell
python scripts/verify_xss_execution.py --mode waf-path --config crs_only --pl 1 `
  --pending-file results/raw/experiments/<run-id>/pending_browser_verification.json
```

`--config` accepts `crs_only`, `ml_only`, or `hybrid`. The verifier checks the
live Compose port binding and, for CRS routes, the configured backend and PL;
it does not silently change the lab configuration. Browser JSON and screenshots
are written under ignored `results/raw/browser/` evidence paths.
