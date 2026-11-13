# Hash audit — hai run 37 case (2026-11-13)

Bản ghi này khóa bằng chứng của hai run chính thức trên corpus 37 case.
Raw evidence bị `.gitignore` (`results/**`) — giữ nguyên các thư mục dưới đây khi
chia sẻ kết quả; hash dưới đây cho phép xác minh chúng không bị sửa.

## Runs

| Run | Backend | Commit | Model serving |
| --- | --- | --- | --- |
| RUN-A `20261113T105850Z-f4deea31` | direct (CRS-only + ML-only) | `5095520` | `lr-tfidf-3cls-1.1` |
| RUN-B `20261113T110057Z-5a65730f` | ml (hybrid CRS→ML) | `5095520` | `lr-tfidf-3cls-1.1` |

Cả hai run: 111 rows = 37 case × PL1–3; `incomplete=0`, `control_invalid_total=0`,
`pending_browser_verification.json` rỗng; metadata ghi `corpus_sha256` cho từng file
corpus (ví dụ `hpp/cases.json` = `cef73937e64d0a65…`).

## SHA-256 artifact model (giống nhau ở cả hai run — mốc v1.1 nguyên vẹn)

- `model.joblib` = `14d536acfb5f4062f671b8c8dc06b073116acaa68cab920bcce675a6d067f2c3` (giống run 36-case `20261112T151032Z`)
- `metrics.json` = `79f52b9fe1093e4dabd5328d2b45840f44c82a35d1ea69a1a6b5fd36fab69977` (giống run 36-case)

## SHA-256 file chính (full)

| File | RUN-A `f4deea31` | RUN-B `5a65730f` |
| --- | --- | --- |
| `results.json` | `19fb3f36940cfd0f65b4f7f3cdc11d588490f50e7f26724ebc38bc4a2f1fe720` | `1ce8689d93a850ab6a7eda7917669dfcfd633d32f5af95c9fef94284d08f4969` |
| `results.csv` | `e636824933e9f9168b54869665e248bf8175115ff0f7fa4cd81a043b396ab279` | `cec14ebece020149162225290995f004b9138a403bf0060d95877aefb0e129c7` |
| `summary.json` | `3178cd02797b647d5d6675d66d0a90dcdca286f7a733e5f85b72bc55dee029fb` | `ea0fd2346394273a701c6fd8096d1760c6fd7f269b0412615dc5ce933c2401c8` |
| `metadata.json` | `29b24a6c08b6692d2a4ad4113f5bbf3d6b7b27b40e51605ea9e171a1ae8a13a5` | `a8b7f14c775efee1543077139a17fd700f6a5cff1d7a0d100905c00097b30c82` |

Full hash từng file PL nằm trong `metadata.json` của run (`source_sha256`).

## So sánh với run 36-case

108 case-round của corpus cũ **giữ nguyên 100% outcome** so với post-G2 candidates
`20261112T171730Z-efb04f02` (direct) và `20261112T171923Z-0a05d016` (hybrid) —
run 37 case chỉ THÊM 3 case-round mới (`hpp-mal-004` × 3 PL).

## Trạng thái model sau bước 1

- Image waf-ml rebuilt từ commit `e6509f2` (guard chống train đè artifact).
- Test trong image mới: 12 tests OK (1 skip vô hại — test model-load không có artifact
  trong tiến trình test).
- Hash model trong container sau rebuild **không đổi** (khớp bảng trên) —
  `ensure_model` giờ chỉ nạp, không train đè trừ khi `ML_FORCE_TRAIN=1`.
