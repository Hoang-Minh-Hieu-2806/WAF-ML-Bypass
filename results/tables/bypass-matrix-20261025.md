# Bypass Matrix — CRS Paranoia Level × 4 nhóm SQLi Evasion (26 case, n=78)

**Run:** `20261025T182650Z-4e5c2027` · **Script:** `scripts/run_experiment.py` · **Stack:** CRS 4.30.0 / ModSec 3.0.17 / nginx (docker `waf-crs` port 8081) · **Oracle:** Spring Lab app (port 8080, logs `logs/application/integrated/app.jsonl`, `X-Lab-Case-ID`) / **ML:** `lr-tfidf-1.0` (F1 0.9076 — GroupKFold5 group=family)
- Malicious: **15** đã phân loại đúng, không có control invalid (1 case ở chi tiết DE-Fix, cc-mal-004 một lần nữa được verify manual)
- Benign: **11** passed comparison (direct app effect == app effect qua WAF)

## Outcome matrix —um 78 lượt (26 case × 3 PL)

| Metric | PL1 | PL2 | PL3 |
|---|---|---|---|
| `blocked` (malicious) | **13/15 = 86.7%** | **13/15 = 86.7%** | 15/15 = 100% |
| `pass_without_effect` (malicious) | 2/15 = 13.3% | 2/15 = 13.3% | 0/15 |
| `allowed` (benign) | 10/11 = 90.9% | 10/11 = 90.9% | 3/11 = 27.3% |
| `benign_blocked` (FPR) | **1/11 = 9.1%** | **1/11 = 9.1%** | **8/11 = 72.7%** |
| `true_bypass` (semantic + detected none) | 0/15 | 0/15 | 0/15 |
| ML classifier (`lr-tfidf-1.0`) | TP 15/15, FP 0/11 | TP 15/15, FP 0/11 | TP 15/15, FP 0/11 |

- **`pass_without_effect` ≠ true bypass** — CRS decode thiếu 2 lượt mà sẽ không có SQL effect (app Flase cũng như CRS "see" payload không semantically unencoded); do đó nó được classify riêng, 0 contributes vào detection-rate cả true-bypass. Nếu cải tiến để mô-tả payload encode đủ là bypass thật thì sẽ làm breach thật — đây là limited decode budget của CRS.
- ML/FPR của `lr-tfidf-1.0` **FPR 0/11 = 0.0% , TP recall 15/15 = 100%** trong tập bypass case này (n=26) — không phải equal với F1 0.9076 trên test set trước đó (n=312, FPR 1.7%).

## Per-technique breakdown

| Technique | Case | PL1 / PL2 | PL3 | flip |
|---|---|---|---|---|
| **HPP (3 ben, 3 mal)** | ben | allowed 3/3 | benign_blocked 3/3 (921180 *HTTP Parameter Pollution* + 932350 *RCE Direct Unix Command Execution*) | flip (0→100% FPR) |
| | mal | 100% blocked | 100% blocked (cùng 942100/942130/942390 + thêm 921180/942460 ở PL3) | giữ |
| **Double-encoding (2 ben, 4 mal)** | ben | allowed 2/2 (920230 *Multiple URL Encoding Detected* chỉ misfire anomaly ở PL2, không vượt threshold 5) | benign_blocked 2/2 (920230 + 920272 *Invalid character in request*) | flip |
| | mal | 2/4 detected+blocked; **de-mal-002/003 pass_without_effect** | 4/4 blocked (nhưng 2/4 chỉ nhờ 920230+920272 — không phải detection SQL payload; `detected` vẫn false cho cặp này) | block tăng, detections giống PL1 |
| **Case-comment (3 ben, 5 mal)** | ben | allowed 3/3 | 1/3 benign_blocked (920272 tiếng Việt) | phân mảnh |
| | mal | 5/5 100% **kể cả cc-mal-001 comment form, cc-mal-003 case-only `oR`** (942100 libinjection) | 5/5 (thêm 932190/932200/942520 RCE family) | giữ 100% |
| **Parsing-discrepancy (3 ben, 3 mal)** | ben | 1/3 benign_blocked (920640 chunked & Content-Type-missing — transport anomaly chứ không payload) | 2/3 benign_blocked | tăng một chút |
| | mal | 3/3 blocked, nhưng **2/3 nhờ transport rules** (920640 Content-Type missing trên chunked, 920170 GET-with-body, 920420 content-type policy) không phải SQL-family | 3/3 giữ | giữ |

- Phí tổng: **CRS block tất cả interventions tổng cộng `blocked+benign_blocked`** – PL1: 14 (13 mal+1 ben), PL2: 14, PL3: 23. Mỗi flip và mỗi rule được lưu trong `pl*.json` in evidence folder.
- 921180 (HPP detection) hoạt động đúng và chỉ ở PL3 bị kích hoạt. CRS ở PL1/PL2 không có rule hiện diện HPP, chặn HPP nhờ libinjection trực tiếp trên giá trị đầu tiên.

## Signature semantic — phân biệt kỹ `blocked` vs `detected`

- 3 case `pd-*` blocked: 2 protocol-only (pd-mal-001 do `920640` Content-Type-missing khi chunked; pd-mal-003 do `920420` content-type policy) và 1 chồng lấn (pd-mal-002 có rule SQL-family `942100` đồng thời `920170` GET-with-body) — pd-mal-002 bị chặn bởi cả hai cơ chế, 2 case còn lại chặn hoàn toàn bởi rule transport.
- 2 case `de-mal-002/003` blocked PL3 chỉ dựa trên rule **920230 (Multiple URL Encoding) + 920272 (Invalid character)** — về mặt SQL-libinjection vẫn không detect — `detected` không tính vì không phải payload-family, nhưng đã bị block.
- ⇒ **Block bằng protocol không thay thế detection** (`detected` đo payload-family; `block%` đo trải nghiệm tổng thể). Báo cáo slide giữa kỳ đã tách brèves hai cột này.

## `pass_without_effect` vs `true_bypass` — phân định cốt lõi

| Case | CRS | App effect | Phân loại | Giải thích |
|---|---|---|---|---|
| de-mal-002 `q=%2527` | allowed, 0 rule | false (Flask decode 1 lượt `'%2527'` literal) | **pass_without_effect** | CRS cũng decode 1 lượt (`t:urlDecodeUni` một pass) — không keyword SQL sinh ra |
| de-mal-003 `id=%25252D` | allowed, 0 rule | false | **pass_without_effect** | CRS decode budget hết trước khi thấy payload; **nhưng** app cũng không decode thêm lượt |
| (không có) | — | — | — | Không case nào trong 26 đạt cả hai điều kiện: CRS không chặn **và** app có semantic effect |

Đối chiếu `docs/interfaces.md` mục 4 (definition consistency): `true_bypass` chỉ tính khi CRS **không chặn** VÀ app thực thi payload (`semantic_effect=true`, `sql_error=null`). Chưa case nào trong 26 đáp ứng cả hai → trên corpus SQLi 4 nhóm này, CRS không để lộ cửa bypass thật.

## Blocked-cơ chế theo PL — SQL-family rule vs protocol rule (dùng cho slide)

Method phân theo sự hiện diện rule-id trong audit của từng case: **SQL-family** = có ≥1 rule `942xxx` (libinjection `942100` + regex SQLi); **protocol** = chỉ rule `92x/921x` (920230 *Multiple URL Encoding*, 920272 *Invalid character*, 920640 *CT-missing*, 920170 *GET-with-body*, 920420 *CT-policy*, 921180 *HPP*). Hai nhóm **không độc lập** — một case có thể kích đồng thời cả hai (cột "chồng lấn"); `949110` (Inbound Anomaly Score) là rule gate xuất hiện ở **13/13/15** case blocked, không tính vào các cột.

| PL | Có rule SQL-family (≥1 rule 942xxx) | — trong đó chồng lấn thêm protocol (92x/921x) | Chỉ rule protocol (không 94x) | Tổng blocked |
|---|---|---|---|---|
| PL1 | **11** (= 10 chỉ-SQL + 1 chồng lấn) | 1 — pd-mal-002 (`942100` + `920170`) | 2 — pd-mal-001 (`920640`), pd-mal-003 (`920420`) | 13 |
| PL2 | **11** (= 8 chỉ-SQL + 3 chồng lấn) | 3 — de-mal-001, de-mal-004 (+`920230`), pd-mal-002 (+`920170`) | 2 — pd-mal-001 (`920640`), pd-mal-003 (`920420`) | 13 |
| PL3 | **11** (= 5 chỉ-SQL + 6 chồng lấn) | 6 — hpp×3 (`921180` HPP), de-mal-001/004 (+`920230/920272`), pd-mal-002 (+`920170`) | 4 — de-mal-002/003 (`920230`+`920272`), pd-mal-001 (`920640`), pd-mal-003 (`920420`) | 15 |

⇒ **CRS chọn "an toàn tuyệt đối" bằng over-blocking ở PL3**: cùng **11 case SQL-family được block mọi PL** (đúng số detected 11/15 ở cả 3 PL), trong khi 2 case DE "không detect" ở PL1/PL2 bị chặn vật lý ở PL3 bằng protocol anomaly rule (chính cơ chế đó tạo FPR 72.7% cho benign). Trade-off kinh điển của signature WAF: càng dồn anomaly threshold lên để chắc chắn chặn mọi biến thể, càng nhiều request hợp lệ bị over-block.

Số rule-instance trên các case blocked (không tính `949110`): PL1 SQL-family 12 / protocol 3; PL2 SQL 54 / protocol 5 (+4 RCE `932xxx` ở case-comment); PL3 SQL 66 / protocol 14 (+13 RCE `932xxx`). RCE `932xxx` không dùng để phân 2 cột (chỉ hiện ở case-comment, luôn đi kèm rule SQL-family).

Nếu cần một câu chốt cho slide: **PL1→PL3: detection SQL-family ổn định 11/15 (73.3%) — cùng 11 case mọi PL; block tổng tăng 13→15/15 (86.7%→100%) khi rule protocol bắt thêm de-mal-002/003 — giá trả: FPR 9.1% → 72.7%, tức benign blocked tăng 8 lần**.
