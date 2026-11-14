# v1.5.1 source-weighted Kaggle candidate

- Baseline: keep the existing private `minhiuwu/v15-train` kernel and its v1.5 outputs unchanged; it records scikit-learn 1.6.1.
- Candidate: private `minhiuwu/v15-source-weighted`; Internet is off. Attach the existing input dataset and the private scikit-learn wheel dataset from `kernel-metadata.json`.
- The candidate discovers the wheel by SHA-256 under `/kaggle/input`; alternatively set `SKLEARN_WHEEL_PATH` to a wheel or a directory of wheels. It fails closed if the version, checksum, Python/platform tags, or dependencies do not match. It never falls back to 1.6.1.
- Pilot completed in private kernel version 4: 100,000 Mendeley rows, HttpParams/lab unchanged, 15.2s fit and 1,294 MB peak RSS. Version 5 is full run (`PILOT_TRAIN_ROWS=0`); a rerun pilot can set `PILOT_TRAIN_ROWS=100000`.
- Candidate keeps all data rows, but caps Mendeley classifier sample-weight sum at 12,288; HttpParams/lab sample weights remain 1. Split cutoff, seed, TF-IDF/LR settings, labels, and threshold remain locked.
- `kaggle kernels push -p waf-ml/kaggle/v1_5_1_source_weighted` pushes/runs a version.
