# ML-WAF v0 — model thật đã vào `/score` (26/10/2026, giữa kỳ T05–06)

Trạng thái: **regex stub đã bị thay bằng model học máy chạy thật trong container
`waf-ml`**, hợp đồng API không đổi. Run evidence: `results/raw/crs-integrated/20261025T172523Z-cecdfdeb/`.

## Cấu hình v0

| Thành phần | Giá trị |
|---|---|
| Pipeline | `TfidfVectorizer(char_wb, ngram 2–5, sublinear_tf)` → `LogisticRegression(C=2.0)` |
| Ngôn ngữ huấn luyện trong image | Python 3.11 + `scikit-learn==1.7.1` (pin trong `waf-ml/requirements.txt`) |
| Dataset v0 | 312 mẫu tự sinh, không RNG: **133 malicious / 179 benign**, 16 family |
| Chia train/val (OOF) | **GroupKFold 5 fold, group = family** — các mutation trùng template (ví dụ `admin' -- `) và benign UTF-8 nằm nguyên nhóm trong fold, không leakage |
| Threshold chuẩn chặn | `score ≥ 0.5` → malicious |
| Randomness | Không (dữ liệu template, GroupKFold deterministic) |
| model_version | `lr-tfidf-1.0` (container) — trường `model_version` trong `metrics.json` |
| Artifact | `model.joblib` (36KB) + `metrics.json` — tại `/app/artifacts` trong container, chỉ tồn tại trong image; tái lập bằng `docker compose build waf-ml` (lần build sau tự train lại) |

## Chỉ số OOF validation (GroupKFold 5-fold, group=family)

| Metric | Giá trị | Chi tiết |
|---|---:|---|
| Accuracy | 92.6% | 289/312 đúng |
| **Precision** (malicious) | 97.4% | 113/116 — 116 mẫu ML flag malicious, 3 là benign thật |
| **Recall / Detection** (malicious) | 85.0% | 113/133 — 20 SQLi bị bỏ qua |
| **F1** | 90.76% | |
| **FPR** (benign bị chặn) | **1.7%** | 3/179 benign bị nhãn malicious (benign chứa `; shipment #732;` / dấu `--` trong notes…) |
| FNR | 15.0% | 20/133 SQLi bị bỏ qua |
| AUROC | 97.6% | |
| Confusion | TN=176 / FP=3 / FN=20 / TP=113 | |

> **Đọc số này sao cho đúng:** đây là **out-of-fold (OOF) validation trên chính
> tập 312 mẫu**, không phải kết quả trên một held-out test set độc lập. Model
> đang serving trên `:8082` được fit trên **toàn bộ 312 mẫu**; corpus nhỏ và tự
> sinh nên số chỉ chứng minh pipeline đúng — không phải benchmark production.

## Detection theo family (phục vụ slide 9: điểm yếu ML đúng chỗ nào)

| Family | Detection | Ghi chú phân tích |
|---|---:|---|
| union (UNION SELECT) | 100% | đặc trưng từ vựng ASCII sạch nhất |
| casing (SeLeCt...) | 100% | ML không nhạy với case — ngược với CRS libinjection |
| tautology-n (1 OR 1=1) | 93.1% | pattern ngắn lặp nhiều |
| tautology-s (' OR 1=1) | 90.0% | hành vi quoting đa dạng |
| time (SLEEP/BENCHMARK) | 80.0% | từ khóa đặc trưng dễ thấy char-gram |
| double-encoding (%2527...) | 80.0% | còn thiếu corpus "%2x" đa mức |
| error (EXTRACTVALUE...) | 77.8% | function-call dễ thấy với char-gram |
| encoding (%27...) | 71.4% | |
| fragment (`1/**/OR/**/1=1`) | 62.5% | thiếu mẫu comment nhiều biến thể |
| boolean (' AND 'a'='a) | 55.6% | gần benign nên phân biệt khó (quoted benign cùng shape) |
| stacked (1; DROP...) | 40.0% | corpus chỉ 5 mẫu cho family; cần mở rộng |

## Kiểm chứng sống `/score` (26/10, dùng curl --data-binary)

| text | label | score |
|---|---|---:|
| `-1 UNION SELECT id,username FROM users` | malicious | 0.9335 |
| `-1'/**/UNION/**/SELECT/**/id,username/**/FROM/**/users--` | malicious | 0.8358 |
| `1; DROP TABLE users --` | malicious | 0.6695 |
| `1 OR 1=1` | malicious | 0.9547 |
| `admin' -- #` | malicious | 0.5057 (boundary threshold — rất tốt cho slide nói về trade-off threshold) |
| `laptop bag` | benign | 0.0963 |
| `mần hình laptop 450` (UTF-8) | benign | 0.0721 |

## Giới hạn (nói với GV)

1. v0 là dataset **nhỏ, tự sinh** — nhiều families chỉ có 5–8 mẫu; số con số trên
   chỉ chứng minh pipeline đúng, **không** là benchmark so sánh với CRS.
2. So sánh CRS vs ML cần đo **end-to-end qua đường chặn** — hiện `waf-ml` vẫn
   chỉ là **scoring API song song**, không nằm trong đường chặn request; proxy
   enforcement chờ chốt trước tuần 07. Trong bypass matrix 25/10 (`../tables/bypass-matrix-20261025.md`),
   ML chỉ được gọi evaluation-only bên cạnh CRS (TP 15/15, FP 0/11 trên 26 case) —
   không phải mô hình chặn inline.
3. Chưa chống XSS (corpus SQLi-only) và chưa có vòng mutation tự tối ưu như
   WAF-A-MoLE — đó là giai đoạn 2 sau giữa kỳ.

## Tái lập

```powershell
# Host (chỉ để đối chiếu số — container mới là authoritative):
python waf-ml/build_dataset.py                          # n=312 malicious=133 benign=179
python waf-ml/train.py --out-dir C:\temp\ml-check      # in metrics JSON
# Hoặc tất cả chạy trong container (tính tái lập chính):
docker compose build waf-ml
docker compose up -d --wait waf-ml
docker compose exec waf-ml cat /app/artifacts/metrics.json
curl.exe -s http://localhost:8082/health                # model_version: lr-tfidf-1.0
```
