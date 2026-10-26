# Baseline và lineage của corpus Long

Baseline nằm ngay trong `dataset/bypass/<technique>/cases.json` với
`role=baseline`. Mutation và negative control chỉ tới baseline qua
`baseline_id`; mutation còn chỉ tới benign và negative qua `control_ids`.
Giữ baseline tại cùng corpus giúp tránh copy drift giữa các thư mục.

Mỗi baseline là SQLi đơn giản tương ứng endpoint của fixture Flask/MySQL.
Baseline phải tạo hiệu ứng ở direct control trước khi coi mutation cùng
family là một phép thử có ngữ nghĩa. Các kỳ vọng hiện là source-reviewed;
không có WAF outcome hoặc runtime evidence trong corpus.

Baseline CRS cũ ở `waf-crs/baseline.json` nhắm SQLite và smoke corpus
`waf-crs/integrated-smoke.json` nhắm MySQL được giữ độc lập. Không gộp sample
counts giữa các corpus hoặc chuyển kỳ vọng parser của SQLite sang Flask.

```powershell
python experiments/corpus.py validate
python experiments/corpus.py preview --technique case-comment
```
