# T03 — ML-based WAF & Evasion Techniques

> **Nghiên cứu WAF học máy và kỹ thuật né tránh: tái lập tấn công đối kháng trên môi trường phòng thí nghiệm**

<p align="center">

![Status](https://img.shields.io/badge/status-in%20development-yellow)
![Project](https://img.shields.io/badge/project-T03-blue)
![Security](https://img.shields.io/badge/domain-Web%20Security-red)
![WAF](https://img.shields.io/badge/WAF-ModSecurity%20%7C%20ML-orange)
![Environment](https://img.shields.io/badge/environment-Docker-blue)
![Ethics](https://img.shields.io/badge/research-ethical%20lab%20only-green)
![License](https://img.shields.io/badge/license-MIT-lightgrey)

</p>

> **Nghiên cứu phòng thủ, thực hiện 100% trên lab local.** Mọi payload trong repo chỉ dùng để
> đánh giá WAF do nhóm tự dựng (Docker: Web App + MySQL + ModSecurity/CRS + ML-WAF).
> Không kiểm thử hệ thống production, không tấn công hệ thống không được cấp phép.
> Chi tiết xem [🔐 Ethical & Safety Scope](#-ethical--safety-scope) và [SECURITY.md](./SECURITY.md).

---

## 📑 Mục lục

- [📌 Giới thiệu](#-giới-thiệu)
- [🎯 Mục tiêu đồ án](#-mục-tiêu-đồ-án)
- [🔬 Phạm vi nghiên cứu](#-phạm-vi-nghiên-cứu)
- [🧪 Các kỹ thuật bypass nghiên cứu](#-các-kỹ-thuật-bypass-nghiên-cứu)
- [🏗️ Kiến trúc hệ thống](#️-kiến-trúc-hệ-thống)
- [🔬 Experimental Pipeline](#-experimental-pipeline)
- [📊 Phương pháp đánh giá](#-phương-pháp-đánh-giá)
- [📋 Experimental Matrix](#-experimental-matrix)
- [🛡️ OWASP CRS Paranoia Level](#️-owasp-crs-paranoia-level)
- [📁 Cấu trúc repository](#-cấu-trúc-repository)
- [🧰 Công nghệ và công cụ](#-công-nghệ-và-công-cụ)
- [📚 Tài liệu tham khảo](#-tài-liệu-tham-khảo)
- [🗓️ Project Roadmap](#️-project-roadmap)
- [👥 Phân công nhóm](#-phân-công-nhóm)
- [🔄 Development Workflow](#-development-workflow)
- [🔐 Ethical & Safety Scope](#-ethical--safety-scope)
- [🎓 Expected Deliverables](#-expected-deliverables)
- [📌 Research Questions](#-research-questions)
- [🧠 Kỹ năng thể hiện](#-kỹ-năng-thể-hiện)
- [📬 Liên hệ](#-liên-hệ)
- [📄 Giấy phép](#-giấy-phép)
- [🚧 Project Status](#-project-status)

---

## 📌 Giới thiệu

**T03 — ML-based WAF & Evasion Techniques** là đồ án nghiên cứu về **Web Application Firewall (WAF)**, tập trung vào việc tìm hiểu khả năng phát hiện tấn công của hai hướng tiếp cận:

1. **Signature-based WAF** — sử dụng ModSecurity kết hợp OWASP Core Rule Set (CRS).
2. **Machine-Learning-based WAF** — WAF sử dụng mô hình học máy để phân loại request.

Đồ án xây dựng một **môi trường lab hoàn toàn local và được kiểm soát**, sau đó tái lập một số kỹ thuật né tránh WAF đã được nghiên cứu và công bố.

Mục tiêu không chỉ là xác định một request có vượt qua WAF hay không, mà quan trọng hơn là **giải thích cơ chế gốc khiến WAF bị vượt qua**, đặc biệt trong các trường hợp có sự khác biệt trong cách WAF và ứng dụng phân tích (parsing) request.

---

## 🎯 Mục tiêu đồ án

### Mục tiêu chính

Đồ án hướng tới việc trả lời các câu hỏi:

- WAF signature-based và ML-based phát hiện request độc hại như thế nào?
- Vì sao một request SQL Injection có thể bị phát hiện ở dạng ban đầu nhưng lại vượt qua sau khi được biến đổi?
- Các kỹ thuật mutation và encoding ảnh hưởng như thế nào đến khả năng phát hiện?
- Sự khác biệt giữa parser của WAF và parser của ứng dụng có thể dẫn đến bypass như thế nào?
- WAF signature-based và ML-based phản ứng khác nhau ra sao trước cùng một tập biến thể?
- Việc tăng **Paranoia Level** của OWASP CRS ảnh hưởng như thế nào đến detection và false positive?
- Có thể đưa ra những khuyến nghị cấu hình nào dựa trên kết quả thực nghiệm?

---

## 🔬 Phạm vi nghiên cứu

### Signature-based WAF

Sử dụng:

- ModSecurity
- OWASP Core Rule Set (CRS)

Đây là baseline chính của đồ án.

### Machine-Learning-based WAF

Xây dựng một WAF ML trong môi trường local.

Pipeline dự kiến:

```text
HTTP Request
     │
     ▼
Preprocessing
     │
     ▼
Feature Extraction / Tokenization
     │
     ▼
ML Model
     │
     ├── Malicious
     │
     └── Benign
```

Mô hình cụ thể sẽ được lựa chọn sau giai đoạn đánh giá dataset và baseline.

---

## 🧪 Các kỹ thuật bypass nghiên cứu

Đồ án tập trung vào bốn nhóm kỹ thuật:

| # | Kỹ thuật | Mục đích nghiên cứu |
|---|---|---|
| 1 | HTTP Parameter Pollution / Fragmentation | Nghiên cứu cách xử lý parameter khác nhau |
| 2 | Double Encoding | Nghiên cứu canonicalization và decoding |
| 3 | Case Variation + SQL Comment | Nghiên cứu signature evasion |
| 4 | Parsing Discrepancy | Nghiên cứu sự khác biệt giữa WAF parser và application parser |

Các kỹ thuật được nghiên cứu trong môi trường lab do nhóm kiểm soát.

---

## 🏗️ Kiến trúc hệ thống

### Tổng quan

```text
                         ┌─────────────────┐
                         │      Client     │
                         │  Test Generator │
                         └────────┬────────┘
                                  │
                                  │ HTTP Request
                                  ▼
                    ┌──────────────────────────┐
                    │       WAF Layer          │
                    │                          │
                    │  ┌────────────────────┐  │
                    │  │ ModSecurity + CRS  │  │
                    │  │ Signature-based    │  │
                    │  └────────────────────┘  │
                    │                          │
                    │  ┌────────────────────┐  │
                    │  │      ML-WAF        │  │
                    │  │ Machine Learning   │  │
                    │  └────────────────────┘  │
                    └────────────┬─────────────┘
                                 │
                                 │ Allowed Request
                                 ▼
                       ┌─────────────────────┐
                       │      Web App        │
                       │   Controlled Target │
                       │   Flask + PyMySQL   │
                       └──────────┬──────────┘
                                  │
                    ┌─────────────┴─────────────┐
                    │                           │
                    ▼                           ▼
          ┌───────────────────┐       ┌─────────────────────┐
           │   MySQL 8.4 LTS (db)  │       │       Logs          │
          │  db:3306, nội bộ  │       │ WAF + Application   │
          │  webnet, không    │       └─────────────────────┘
          │  expose ra host   │
          └───────────────────┘
```

> **MySQL-first:** Web App kết nối qua `DATABASE_URL=mysql://root:${DB_PASS}@db:3306/waf_lab`. Schema/seed track ở `docker/db/init/`, runtime `mysql-data` volume bị ignore. DB chỉ listen nội bộ `webnet`.


---

## 🔬 Experimental Pipeline

Mỗi thí nghiệm sẽ được thực hiện theo pipeline:

```text
Original Payload
       │
       ▼
Baseline Test
       │
       ▼
Payload Mutation
       │
       ▼
Send to WAF
       │
       ├───────────────┐
       │               │
    Blocked          Allowed
       │               │
       ▼               ▼
   Record           Web App
   Result               │
                       ▼
                  Application
                   Behavior
                       │
                       ▼
                 Analyze Cause
```

Đối với mỗi test case, nhóm sẽ ghi nhận:

- WAF decision;
- HTTP response;
- application behavior;
- WAF log;
- application log;
- kỹ thuật mutation được sử dụng;
- nguyên nhân bypass nếu có.

Đối với parsing discrepancy, nhóm tập trung phân tích sự khác biệt giữa:

```text
WAF Parser
    ≠
Application Parser
```

---

## 📊 Phương pháp đánh giá

### Detection Rate

Tỷ lệ request độc hại được WAF phát hiện:

```text
Detection Rate =
Detected Malicious Requests
--------------------------- × 100%
Total Malicious Requests
```

### Bypass Rate

Tỷ lệ request độc hại vượt qua WAF:

```text
Bypass Rate =
Successful Bypass Requests
-------------------------- × 100%
Total Malicious Requests
```

### False Positive Rate

Tỷ lệ request hợp lệ nhưng bị WAF chặn:

```text
False Positive Rate =
Benign Requests Blocked
----------------------- × 100%
Total Benign Requests
```

### False Negative Rate

Tỷ lệ request độc hại không được WAF phát hiện:

```text
False Negative Rate =
Malicious Requests Missed
------------------------- × 100%
Total Malicious Requests
```

Đối với ML-WAF, đánh giá thêm:

- Accuracy
- Precision
- Recall
- F1-score
- False Positive Rate
- False Negative Rate

---

## 📋 Experimental Matrix

Kết quả cuối cùng dự kiến được tổng hợp:

| Technique | Total Tests | CRS Blocked | CRS Bypass | ML Blocked | ML Bypass |
|---|---:|---:|---:|---:|---:|
| Baseline | TBD | TBD | TBD | TBD | TBD |
| HPP / Fragmentation | TBD | TBD | TBD | TBD | TBD |
| Double Encoding | TBD | TBD | TBD | TBD | TBD |
| Case + SQL Comment | TBD | TBD | TBD | TBD | TBD |
| Parsing Discrepancy | TBD | TBD | TBD | TBD | TBD |

`TBD` sẽ được thay thế bằng kết quả thực nghiệm thực tế.

---

## 🛡️ OWASP CRS Paranoia Level

Một phần của đồ án là nghiên cứu ảnh hưởng của **Paranoia Level** đối với khả năng phát hiện.

Dự kiến đánh giá:

```text
Paranoia Level 1
       │
       ▼
Baseline
       │
       ▼
Paranoia Level 2
       │
       ▼
Paranoia Level 3
       │
       ▼
Compare Results
```

Các yếu tố được theo dõi:

- Detection Rate
- Bypass Rate
- False Positive Rate
- False Negative Rate
- số lượng rule được kích hoạt
- các loại request bị ảnh hưởng

Mục tiêu là đánh giá sự cân bằng giữa:

```text
Security
    ↕
False Positive
```

và đưa ra khuyến nghị dựa trên kết quả thực nghiệm.

---

## 📁 Cấu trúc repository

```text
WAF-ML-Bypass/
│
├── dataset/
│   ├── raw/
│   │   └── .gitkeep
│   ├── processed/
│   │   └── .gitkeep
│   └── bypass/
│       ├── hpp/
│       │   └── .gitkeep
│       ├── double-encoding/
│       │   └── .gitkeep
│       ├── case-comment/
│       │   └── .gitkeep
│       └── parsing-discrepancy/
│           └── .gitkeep
│
├── docker/
│   ├── db/init/
│   │   ├── 01-schema.sql
│   │   └── 02-seed.sql
│   ├── waf-crs/              ← lab SQLite độc lập (Huy)
│   │   ├── Dockerfile
│   │   ├── Dockerfile.backend
│   │   └── compose.yml
│   ├── waf-ml/
│   │   └── Dockerfile
│   └── web-app/
│       └── Dockerfile
│
├── .dockerignore
├── .env.example
├── docker-compose.yml        ← lab tích hợp 4 service
│
├── docs/
│   ├── architecture.md
│   ├── interfaces.md
│   ├── quickstart-lab.md
│   └── waf-crs.md
│
├── experiments/
│   ├── baseline/
│   │   └── .gitkeep
│   ├── hpp/
│   │   └── .gitkeep
│   ├── double-encoding/
│   │   └── .gitkeep
│   ├── case-comment/
│   │   └── .gitkeep
│   └── parsing-discrepancy/
│       └── .gitkeep
│
├── logs/
│   ├── waf/
│   │   ├── .gitkeep
│   │   └── integrated/
│   │       └── .gitkeep
│   └── application/
│       ├── .gitkeep
│       └── integrated/
│           └── .gitkeep
│
├── report/
│   ├── crs-docker-integration.md
│   └── waf-crs-baseline.md
│
├── results/
│   ├── raw/
│   │   └── .gitkeep
│   ├── tables/
│   │   └── .gitkeep
│   └── graphs/
│       └── .gitkeep
│
├── scripts/
│   ├── README.md
│   ├── requirements-attack.txt
│   └── .gitkeep
│
├── waf-crs/
│   ├── README.md
│   ├── baseline.json
│   ├── integrated-smoke.json
│   ├── run_baseline.py
│   ├── run_integrated_smoke.py
│   ├── test_backend.py
│   └── test_baseline.py
│
├── waf-ml/
│   ├── app.py
│   └── requirements.txt
│
└── web-app/
    ├── app.py
    ├── requirements.txt
    └── test_app.py
```

### Vai trò các thư mục

| Directory | Vai trò | Vai trò phụ trách (xem bảng 👥 Phân công nhóm) |
|---|---|---|
| `dataset/raw/` | Dataset gốc chưa xử lý | ML Engineer |
| `dataset/processed/` | Dataset sau preprocessing | ML Engineer |
| `dataset/bypass/` | Các test case phục vụ bypass experiments | Bypass Research |
| `dataset/bypass/hpp/` | Test cases HPP / Fragmentation | Bypass Research |
| `dataset/bypass/double-encoding/` | Test cases Double Encoding | Bypass Research |
| `dataset/bypass/case-comment/` | Test cases Case Variation + SQL Comment | Bypass Research |
| `dataset/bypass/parsing-discrepancy/` | Test cases Parsing Discrepancy | Bypass Research |
| `docker/` + `docker-compose.yml` | Deployment 4 service web-app / waf-crs / waf-ml / db (mysql:8.4 LTS) | Architecture & Integration |
| `docker/db/init/` | Schema + seed MySQL (`01-schema.sql`, `02-seed.sql`, track trong git) | Architecture & Integration |
| `.env.example` | Mẫu biến môi trường (`DB_PASS`, `DATABASE_URL`) | Architecture & Integration |
| `docker/waf-crs/` | Docker configuration/runtime setup cho ModSecurity + CRS | WAF Signature |
| `docker/waf-ml/` | Docker configuration/runtime setup cho ML-WAF | ML Engineer (+ Architecture tích hợp) |
| `docker/web-app/` | Docker configuration/runtime setup cho web application | Architecture & Integration |
| `waf-crs/` | Configuration, rule customization và tài liệu riêng của CRS WAF | WAF Signature |
| `waf-ml/` | Source code và configuration của ML-WAF | ML Engineer |
| `web-app/` | Source code của web application mục tiêu trong lab | Architecture & Integration |
| `experiments/` | Tổ chức các experiment theo từng nhóm | Bypass Research + Automation & Evaluation |
| `experiments/baseline/` | Baseline testing trước khi mutation | WAF Signature + Automation & Evaluation |
| `experiments/hpp/` | Experiment HPP / Fragmentation | Bypass Research |
| `experiments/double-encoding/` | Experiment Double Encoding | Bypass Research |
| `experiments/case-comment/` | Experiment Case Variation + SQL Comment | Bypass Research |
| `experiments/parsing-discrepancy/` | Experiment Parsing Discrepancy | Bypass Research |
| `scripts/` | Script tự động hóa testing và data processing | Automation & Evaluation |
| `logs/waf/` | Log từ WAF (runtime, không commit) | WAF Signature / ML Engineer |
| `logs/application/` | Log từ web application (runtime, không commit) | Architecture & Integration |
| `results/raw/` | Kết quả thô từ experiments (runtime, không commit) | Automation & Evaluation |
| `results/tables/` | Bảng kết quả đã tổng hợp | Automation & Evaluation |
| `results/graphs/` | Biểu đồ và visualization | Automation & Evaluation |
| `docs/` | Technical documentation và research notes | Tất cả (mỗi module ≥1 file .md) |
| `report/` | Tài liệu phục vụ báo cáo cuối kỳ | Tất cả (theo phần trách nhiệm) |

### `docker/` và các thư mục module khác nhau như thế nào?

Repository tách **deployment configuration** và **module implementation**:

```text
docker/
    │
    ├── db/init/         → Schema + seed MySQL (track, init lúc db start)
    ├── waf-crs/       → Cách chạy WAF bằng Docker
    ├── waf-ml/        → Cách chạy ML-WAF bằng Docker
    └── web-app/       → Cách chạy web app bằng Docker (Flask + PyMySQL -> db:3306)

waf-crs/               → Configuration / customization của CRS
waf-ml/                → Source code của ML-WAF
web-app/               → Source code của web application
```

> Runtime `mysql-data` volume và `.env` local bị ignore. Chỉ `docker/db/init/*.sql` + `.env.example` được commit.

Cách tổ chức này giúp tách:

```text
Application / Configuration
            +
Deployment / Runtime
```

và thuận tiện cho việc quản lý container độc lập.

---

## 🧰 Công nghệ và công cụ

### Core

- Docker
- Docker Compose
- ModSecurity
- OWASP Core Rule Set
- Python
- MySQL 8.4 LTS (service `db`, chỉ nội bộ `webnet`, volume `mysql-data` bị ignore; `8.0.x` đã EOL 4/2026 nên lab dùng `8.4`)
- PyMySQL (Web App kết nối qua `DATABASE_URL=mysql://root:${DB_PASS}@db:3306/waf_lab`)
- Git
- GitHub

### Security Testing

- wafw00f
- sqlmap
- WAF-A-MoLE
- Custom testing scripts

### Machine Learning

Dự kiến sử dụng:

- Python
- NumPy
- Pandas
- scikit-learn

Mô hình cụ thể sẽ được lựa chọn sau khi đánh giá dataset và baseline.

### Visualization

- Matplotlib
- Pandas
- Jupyter Notebook

---

## 🚀 Quick Start

**Module CRS độc lập:** baseline PL1–PL3 đã có evidence trên fixture Python/SQLite.

```powershell
python -m unittest discover -s waf-crs -p test_baseline.py -v
python waf-crs/run_baseline.py
```

Lab riêng dùng `127.0.0.1:18080/18081`; xem [hướng dẫn CRS](docs/waf-crs.md)
và [báo cáo baseline](report/waf-crs-baseline.md). Corpus, runner và evidence
SQLite được giữ riêng với kết quả của backend Flask/MySQL.

**Lab tích hợp:** 4 service từ `feature/docker`, CRS blocking + JSON audit,
application evidence có correlation ID. ML `/score` chạy model học máy
lr-tfidf-1.0 (F1 0.9076 — OOF validation GroupKFold5 trên n=312, không phải
held-out test set; scoring API, chưa nằm trong đường chặn). Bypass SQLi
4 nhóm có runner `scripts/run_experiment.py` + evidence
`results/raw/experiments/`.
Xem [Quick Start PowerShell](docs/quickstart-lab.md) để dựng lab và chạy
`python waf-crs/run_integrated_smoke.py` kiểm chứng PL1.
[Kết quả tích hợp PL1–PL3](report/crs-docker-integration.md) được lưu riêng với
baseline SQLite.

> Chỉ chạy trên lab local. `.env` chứa mật khẩu lab và không được commit.


```bash
# Clone repository
git clone <repository-url>

# Enter project directory
cd WAF-ML-Bypass

# Copy env mẫu rồi đổi DB_PASS thành giá trị riêng (không dùng default cho dữ liệu thật)
cp .env.example .env

# Start the lab (4 service: web-app, waf-crs, waf-ml, db) và chờ healthy
docker compose up -d --build --wait --wait-timeout 240
docker compose ps   # expect waf-app, waf-crs, waf-ml, waf-db healthy

# Smoke test: 8080 = web-app trực tiếp, 8081 = qua CRS WAF, 8082 = ML scoring API
curl -i "http://localhost:8081/search?q=test"                 # benign -> 200
curl -i "http://localhost:8081/product?id=1%20OR%201%3D1"     # SQLi   -> 403
curl -s http://localhost:8082/health
echo '{"text":"1 OR 1=1"}' | curl -s -X POST http://localhost:8082/score -H "Content-Type: application/json" -d "@-"

# Đối chiếu WAF vs App trên MySQL: correlation ID, PL, evidence (mặc định PL1)
python waf-crs/run_integrated_smoke.py

# Regression tests (test app cần Flask/PyMySQL trong Python đang dùng)
python -m unittest discover -s waf-crs -p test_baseline.py -v
python -m unittest discover -s web-app -p test_app.py -v

# Kiểm tra DB (thay <DB_PASS> bằng giá trị trong .env của bạn)
docker compose exec db mysql -uroot -p"<DB_PASS>" -e "SELECT * FROM waf_lab.users;"
```

> Chi tiết đầy đủ (PL1–PL3, rollback, log paths): [docs/quickstart-lab.md](docs/quickstart-lab.md).
> Trên Windows, nếu đường dẫn repo chứa ký tự ngoài cp1252 (ví dụ `Bảo mật web và app`),
> đặt `$env:PYTHONUTF8='1'` trước khi chạy runner Python.

---

## 📚 Tài liệu tham khảo

### WAF-A-MoLE

Demetrio et al. (2020).

> **WAF-A-MoLE: An Adversarial Machine Learning Framework for Web Application Firewalls**

Proceedings of the 35th Annual ACM Symposium on Applied Computing.

DOI:

`10.1145/3341105.3373962`

---

### AdvSQLi

Qu et al. (2024).

> **AdvSQLi: Generating Adversarial SQL Injections Against Real-World WAF-as-a-Service**

IEEE Transactions on Information Forensics and Security.

DOI:

`10.1109/TIFS.2024.3350911`

---

### WAFBooster

Wu et al. (2025).

> **WAFBooster: Automatic Boosting of WAF Security Against Mutated Malicious Payloads**

IEEE Transactions on Dependable and Secure Computing.

DOI:

`10.1109/TDSC.2024.3429271`

---

### Signature-based vs Machine-Learning-based WAF

Applebaum et al. (2021).

> **Signature-based and Machine-Learning-based Web Application Firewalls: A Short Survey**

Procedia Computer Science.

DOI:

`10.1016/j.procs.2021.05.105`

---

### Deep Learning WAF

Dawadi et al. (2023).

> **Deep Learning Technique-Enabled Web Application Firewall for the Detection of Web Attacks**

Sensors.

DOI:

`10.3390/s23042073`

---

### WAFFLED

Akhavani et al. (2025).

> **WAFFLED: Exploiting Parsing Discrepancies to Bypass Web Application Firewalls**

2025 IEEE Annual Computer Security Applications Conference (ACSAC).

DOI:

`10.1109/ACSAC67867.2025.00062`

---

## 🗓️ Project Roadmap

Đồ án triển khai trong **12 tuần (triển khai lặp)**, theo kế hoạch nội bộ của nhóm.

```text
Tuần 01–02: Tổng quan & Lab Docker
  - Nghiên cứu ModSecurity+CRS, ML-WAF, kỹ thuật bypass
  - Thiết kế kiến trúc Web App + MySQL, schema test-case/result, repo + branch dev
  - MILESTONE: docker compose up -d --build chạy 4 container (waf-app, waf-crs, waf-ml, waf-db healthy), web-app :8080 trả 200 — ✅ 13/10/2026
        │
        ▼
Tuần 03–04: ModSecurity + CRS & Baseline
  - Web App 3 endpoint (GET /search, GET /product, POST /login) + app.log, query MySQL waf_lab.users
  - ModSecurity v3 + OWASP CRS, blocking, audit log
  - Bộ baseline ≥10 case (5 benign / 5 malicious), tính Detection & FPR
  - MILESTONE: SQLi mẫu bị 403 + rule ID, benign được forward 200 — ✅ 10/10/2026 (SQLite PL1–PL3), ✅ 18/10/2026 (tích hợp Flask/MySQL)
        │
        ▼
Tuần 05–06: ML-WAF Pipeline & Đào tạo Model
  - dataset/raw (SQLi + benign), schema CSV/JSON, TF-IDF/BOW
  - Logistic Regression, GroupKFold theo family (chống leakage), OOF validation
  - API scoring Flask/FastAPI {label, score} + version model
  - MILESTONE: curl 1 request vào ML-WAF nhận được nhãn, chạy song song CRS — ✅ 25/10/2026: model thật `lr-tfidf-1.0` đã vào `/score` (health trả `ok`, bỏ stub; đánh giá OOF GroupKFold5 n=312: F1 0.9076, FPR 1.68%)
        │
        ▼
Tuần 07–08: Bypass HPP & Double-Encoding
  - Đóng băng schema test-case JSON, payload HPP + double-encoding
  - scripts/run_experiment.py chạy qua cả CRS và ML-WAF, so sánh audit.log vs app log
  - MILESTONE: bảng block/allow CRS vs ML cho 2 kỹ thuật + nguyên nhân bypass
        │
        ▼
Tuần 09: Case Variation + SQL Comment
  - Payload SeLeCt, comment --/#, kiểm tra CRS rule logs + độ nhạy ML
  - MILESTONE: so sánh CRS vs ML cho case/comment + phân tích nguyên nhân
        │
        ▼
Tuần 10: Parsing Discrepancy
  - 1–2 kiểu (duplicate params / trailer headers / chunked...), trích WAFFLED
  - MILESTONE: demo 1 case WAF không thấy nhưng app thực thi + sơ đồ luồng
        │
        ▼
Tuần 11: Tổng hợp & Phân tích
  - Gộp results, tính Detection / Bypass / FPR / FNR + Precision/Recall/F1 riêng cho CRS và ML theo từng kỹ thuật
  - Bar chart CRS vs ML, rule ID kích hoạt nhiều nhất
  - MILESTONE: bảng tổng kết điểm số theo từng kỹ thuật
        │
        ▼
Tuần 12: Hardening & Báo cáo
  - Tăng Paranoia Level PL1→PL3, đo lại detection vs FP, đề xuất đánh đổi
  - Báo cáo (Giới thiệu, Kiến trúc, Thực nghiệm, Kết quả, Phân tích, Hardening, Kết luận) + slide demo
  - MILESTONE: lab đầy đủ + báo cáo thô + slide có dữ liệu
```

> *Lưu ý: thời hạn thực tế linh hoạt ±1 tuần tùy tiến độ.*

---

## 👥 Phân công nhóm

**Đội dự án**: 5 thành viên — Hoàng Minh Hiếu, Châu Gia Huy, Đặng Văn Hoàng, Lê Đình Long, Huỳnh Như Hoàng.

> Danh sách dưới đây là phân công vai trò công khai cho mục đích học thuật/CV.
> Không đăng tải MSSV, email, số điện thoại hoặc thông tin cá nhân khác trong repo công khai.

| Thành viên | Trách nhiệm chính | Files / Modules đảm nhận | Nhiệm vụ cụ thể (Checklist) |
|---|---|---|---|
| **Hoàng Minh Hiếu** | Kiến trúc & Tích hợp tổng thể | `docker/`, `docker-compose.yml`, `docker/db/`, `.env.example`, `docs/` (chốt interface; `scripts/` do Automation & Evaluation implement) | - Thiết kế Docker Compose 4 service **web-app, waf-crs, waf-ml, db (mysql:8.4 LTS)**; <br> - Đảm bảo network & port không trùng, DB chỉ nội bộ `webnet`; <br> - Quản lý `docker/db/init/*.sql` + `.env.example` (`DB_PASS`, `DATABASE_URL`); <br> - Cài đặt giao thức nội bộ giữa các container; <br> - Viết tài liệu hướng dẫn chạy lab (Quick Start). |
| **Châu Gia Huy** | WAF Signature (ModSecurity + CRS) | `waf-crs/`, `docker/waf-crs/` | - Cài đặt ModSecurity 3.x + OWASP CRS mới nhất; <br> - Cấu hình blocking + audit log chi tiết; <br> - Kiểm tra rule SQLi mẫu (phải bị chặn 403); <br> - Thiết lập 3 mức Paranoia Level và so sánh sơ bộ. |
| **Đặng Văn Hoàng** | Machine-Learning WAF | `waf-ml/`, `docker/waf-ml/`, `dataset/` | - Chuẩn bị dataset labeled (SQLi, XSS, benign); <br> - Tiền xử lý (tokenize, vectorize TF-IDF/BOW); <br> - Huấn luyện baseline (Logistic Regression / SVM); <br> - Cung cấp API Flask/FastAPI `{label, score}`; <br> - Quản lý phiên bản model. |
| **Lê Đình Long** | Bypass Research (Payloads) | `dataset/bypass/`, `experiments/` | - Xây test-case cho 4 kỹ thuật (HPP, double-encoding, case/comment, parsing-discrepancy) theo schema thống nhất; <br> - Phát triển payload ví dụ và đối chứng; <br> - Phân tích khác biệt parser WAF vs App; <br> - Soạn tài liệu kỹ thuật từng kỹ thuật. |
| **Huỳnh Như Hoàng** | Tự động hóa & Đánh giá | `scripts/`, `results/`, `experiments/` | - Viết `scripts/run_experiment.py`: gửi request, thu thập quyết định WAF & App, lưu CSV/JSON; <br> - Tính metrics (Detection, Bypass, FPR, FNR, Precision, Recall, F1); <br> - Vẽ biểu đồ so sánh CRS vs ML; <br> - Bảo đảm kết quả tái lập được. |

> Mỗi thành viên **(1)** tự hiểu pipeline end-to-end, **(2)** phối hợp về giao diện chung (schema test-case, định dạng log, API scoring), **(3)** review lẫn nhau. Không ai làm toàn bộ riêng lẻ — cần liên tục tích hợp.

---

## 🔄 Development Workflow

Repository dùng GitFlow: `main` là stable, `dev` là nhánh tích hợp. Mỗi tính năng phát triển trên branch riêng (`feature/<name>`).

Mỗi thành viên phát triển trên feature branch:

```text
main (stable)
  │
  └── dev (tích hợp)
        │
        ├── feature/docker
        ├── feature/crs
        ├── feature/ml-waf
        ├── feature/bypass
        └── feature/experiments
```

> Chi tiết ai phụ trách branch nào xem bảng [👥 Phân công nhóm](#-phân-công-nhóm). Bảng trên chỉ nêu quy ước đặt tên branch.

Quy trình:

```text
Feature Branch
      │
      ▼
   Commit
      │
      ▼
Pull Request (vào dev)
      │
      ▼
Review (>=1 thành viên) + Smoke-test
      │
      ▼
dev → main (khi stable)
```

### Quy tắc

- Không push trực tiếp vào `main` / `dev`. Mọi thay đổi qua PR + review.
- Mỗi PR tối thiểu qua smoke-test: web-app trả 200, WAF chặn payload SQLi mẫu (403), ML-WAF trả nhãn, runner script output đúng schema CSV/JSON.
- Thay đổi chung (docker-compose, schema test-case, định dạng log/API) phải qua review nhóm. Cấm edit chồng lấp sai thư mục sở hữu (xem bảng Phân công nhóm).
- Không commit secret/credential. Không commit dataset raw, logs, model binaries (đã cấu hình `.gitignore`).
- Experiment phải có cách tái lập rõ ràng.
- Commit message mô tả rõ thay đổi.

---

## 🔐 Ethical & Safety Scope

Đây là **security research project** được thực hiện trong môi trường kiểm soát.

Tất cả thử nghiệm phải:

- chạy trên hệ thống local/lab;
- sử dụng web application do nhóm kiểm soát;
- không kiểm thử WAF production của bên thứ ba;
- không sử dụng payload để tấn công hệ thống không được cấp phép;
- không thu thập dữ liệu cá nhân;
- không đưa credential hoặc secret vào repository.

Mục tiêu của đồ án là:

> **Hiểu cơ chế phòng thủ, xác định điểm yếu trong môi trường kiểm soát và đề xuất phương pháp hardening.**

---

## 🎓 Expected Deliverables

### 1. Working WAF Lab

```text
ModSecurity + OWASP CRS
             +
          ML-WAF
             +
         Web App
```

### 2. Bypass Test Suite

Các test case cho:

- HPP / Fragmentation
- Double Encoding
- Case Variation + SQL Comment
- Parsing Discrepancy

### 3. Automated Testing

Pipeline:

```text
Payload
   ↓
Send
   ↓
WAF
   ↓
Record
   ↓
Analyze
```

### 4. Experimental Dataset

```text
Raw
 ↓
Processed
 ↓
Baseline
 ↓
Mutated
 ↓
Evaluated
```

### 5. Quantitative Results

Bao gồm:

- Detection Rate
- Bypass Rate
- False Positive Rate
- False Negative Rate
- Precision
- Recall
- F1-score

### 6. Visualization

Biểu đồ so sánh:

```text
Signature WAF
      vs
    ML-WAF
```

theo từng kỹ thuật bypass.

### 7. CRS Hardening Recommendations

Đề xuất cấu hình dựa trên:

- kết quả thực nghiệm;
- Paranoia Level;
- detection capability;
- false positive;
- bypass behavior.

### 8. Research Report

```text
Background
    ↓
Related Work
    ↓
Architecture
    ↓
Methodology
    ↓
Implementation
    ↓
Experiments
    ↓
Results
    ↓
Analysis
    ↓
Hardening
    ↓
Conclusion
```

---

## 📌 Research Questions

### RQ1

**How effective are signature-based and ML-based WAFs against mutated malicious requests?**

### RQ2

**Which evasion techniques produce the highest bypass rate in the controlled environment?**

### RQ3

**How do encoding, parameter handling and parser differences affect WAF detection?**

### RQ4

**How does increasing OWASP CRS Paranoia Level affect detection and false positives?**

### RQ5

**What are the fundamental reasons behind successful bypasses?**

---

## 🧠 Kỹ năng thể hiện

Repository này thể hiện các kỹ năng phục vụ CV:

- Triển khai lab bảo mật bằng **Docker / Docker Compose** (multi-service, network nội bộ, healthcheck).
- Cấu hình **ModSecurity + OWASP CRS** (blocking, audit log, Paranoia Level).
- Xây dựng Web App **Flask + PyMySQL** có logging đối chiếu WAF log vs App log.
- Pipeline ML cơ bản: **TF-IDF + Logistic Regression/SVM (scikit-learn)**, đánh giá Precision/Recall/F1, chống data leakage.
- Tự động hóa thực nghiệm bằng Python, tổng hợp CSV/JSON và trực quan hóa kết quả.

---

## 📬 Liên hệ

- Nhóm thực hiện 5 thành viên, xem chi tiết ở [👥 Phân công nhóm](#-phân-công-nhóm).
- Trao đổi chuyên môn qua GitHub Issues của repository này.
- Vui lòng không gửi credential, dữ liệu cá nhân hoặc log production qua kênh công khai.

---

## 📄 Giấy phép

- Mã nguồn: [MIT License](./LICENSE).
- Chính sách bảo mật và phạm vi nghiên cứu có trách nhiệm: [SECURITY.md](./SECURITY.md).

---

## 🚧 Project Status

**Status: Docker lab + CRS baseline/integration + ML model (lr-tfidf-1.0) + bypass experiments (26 case × PL1–3) đã hoàn thành và có evidence; còn lại: phân tích sâu (precision/recall per-technique), ML enforcement path và hardening**

### Completed

- [x] Repository created
- [x] Git initialized
- [x] Initial repository structure created
- [x] Research scope defined
- [x] Experimental categories defined
- [x] Initial README created
- [x] Docker lab 4 service healthy (waf-app, waf-crs, waf-ml, waf-db) — 13/10/2026
- [x] Controlled web application Flask + PyMySQL + MySQL 8.4, 3 endpoint + app evidence JSONL
- [x] ModSecurity + OWASP CRS: baseline SQLite PL1–PL3 (13 case) + tích hợp Flask/MySQL (18/10/2026)
- [x] Hợp đồng tích hợp và tài liệu: `docs/architecture.md`, `docs/interfaces.md`, `docs/quickstart-lab.md`, `docs/waf-crs.md`

### In Progress

- [ ] Finalize system architecture (còn chốt ML enforcement path trước tuần 07 — xem `docs/architecture.md`)
- [x] Prepare ML dataset (25/10/2026: 312 mẫu — 133 mal / 179 ben / 16 family; OOF GroupKFold5 → `results/tables/ml-v0-summary.md`)
- [x] Implement ML-WAF (tuần 05–06; model lr-tfidf-1.0, giữ nguyên contract `/score`)
- [x] Bypass experiments HPP / double-encoding / case-comment / parsing-discrepancy (25/10/2026: corpus 26 case + matrix PL1–3 → `results/tables/bypass-matrix-20261025.md`; ⏳ còn phân tích per-technique và re-run trên ML enforcement path sau khi chốt proxy)
- [x] Build automated testing pipeline (`scripts/run_experiment.py` — corpus 26 case, matrix PL1–3)
- [ ] Analyze results
- [ ] CRS hardening
- [ ] Final report
- [ ] Final presentation

---

<p align="center">

**T03 — ML-based WAF & Evasion Techniques**

*Web Security Research Project*

</p>
