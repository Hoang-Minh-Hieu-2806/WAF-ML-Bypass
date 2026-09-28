# T03 — ML-based WAF & Evasion Techniques

> **Nghiên cứu WAF học máy và kỹ thuật né tránh: tái lập tấn công đối kháng trên môi trường phòng thí nghiệm**

<p align="center">

![Status](https://img.shields.io/badge/status-in%20development-yellow)
![Project](https://img.shields.io/badge/project-T03-blue)
![Security](https://img.shields.io/badge/domain-Web%20Security-red)
![WAF](https://img.shields.io/badge/WAF-ModSecurity%20%7C%20ML-orange)
![Environment](https://img.shields.io/badge/environment-Docker-blue)

</p>

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
                       └──────────┬──────────┘
                                  │
                                  ▼
                       ┌─────────────────────┐
                       │       Logs          │
                       │ WAF + Application   │
                       └─────────────────────┘
```

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
│   ├── waf-crs/
│   │   └── .gitkeep
│   ├── waf-ml/
│   │   └── .gitkeep
│   └── web-app/
│       └── .gitkeep
│
├── docs/
│   └── .gitkeep
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
│   │   └── .gitkeep
│   └── application/
│       └── .gitkeep
│
├── report/
│   └── .gitkeep
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
│   └── .gitkeep
│
├── waf-crs/
│   └── .gitkeep
│
├── waf-ml/
│   └── .gitkeep
│
└── web-app/
    └── .gitkeep
```

### Vai trò các thư mục

| Directory | Vai trò |
|---|---|
| `dataset/raw/` | Dataset gốc chưa xử lý |
| `dataset/processed/` | Dataset sau preprocessing |
| `dataset/bypass/` | Các test case phục vụ bypass experiments |
| `dataset/bypass/hpp/` | Test cases HPP / Fragmentation |
| `dataset/bypass/double-encoding/` | Test cases Double Encoding |
| `dataset/bypass/case-comment/` | Test cases Case Variation + SQL Comment |
| `dataset/bypass/parsing-discrepancy/` | Test cases Parsing Discrepancy |
| `docker/` | Các file phục vụ deployment bằng Docker |
| `docker/waf-crs/` | Docker configuration/runtime setup cho ModSecurity + CRS |
| `docker/waf-ml/` | Docker configuration/runtime setup cho ML-WAF |
| `docker/web-app/` | Docker configuration/runtime setup cho web application |
| `waf-crs/` | Configuration, rule customization và tài liệu riêng của CRS WAF |
| `waf-ml/` | Source code và configuration của ML-WAF |
| `web-app/` | Source code của web application mục tiêu trong lab |
| `experiments/` | Tổ chức các experiment theo từng nhóm |
| `experiments/baseline/` | Baseline testing trước khi mutation |
| `experiments/hpp/` | Experiment HPP / Fragmentation |
| `experiments/double-encoding/` | Experiment Double Encoding |
| `experiments/case-comment/` | Experiment Case Variation + SQL Comment |
| `experiments/parsing-discrepancy/` | Experiment Parsing Discrepancy |
| `scripts/` | Script tự động hóa testing và data processing |
| `logs/waf/` | Log từ WAF |
| `logs/application/` | Log từ web application |
| `results/raw/` | Kết quả thô từ experiments |
| `results/tables/` | Bảng kết quả đã tổng hợp |
| `results/graphs/` | Biểu đồ và visualization |
| `docs/` | Technical documentation và research notes |
| `report/` | Tài liệu phục vụ báo cáo cuối kỳ |

### `docker/` và các thư mục module khác nhau như thế nào?

Repository tách **deployment configuration** và **module implementation**:

```text
docker/
    │
    ├── waf-crs/       → Cách chạy WAF bằng Docker
    ├── waf-ml/        → Cách chạy ML-WAF bằng Docker
    └── web-app/       → Cách chạy web app bằng Docker

waf-crs/               → Configuration / customization của CRS
waf-ml/                → Source code của ML-WAF
web-app/               → Source code của web application
```

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

> **Status: Planned**

Quick Start sẽ được hoàn thiện sau khi Docker lab được triển khai.

Dự kiến quy trình:

```bash
# Clone repository
git clone <repository-url>

# Enter project directory
cd WAF-ML-Bypass

# Start the lab
docker compose up -d

# Check running containers
docker compose ps

# Run experiments
# TBD
```

Các command chính thức sẽ được cập nhật sau khi hoàn thành Phase 1.

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

Đồ án dự kiến triển khai trong **12 tuần**.

```text
Week 01–02
Research + Architecture
        │
        ▼
Week 03–04
Docker Lab + Web Application
        │
        ▼
Week 05–06
ModSecurity/CRS + ML-WAF
        │
        ▼
Week 07–09
Bypass Experiments
        │
        ▼
Week 10
Evaluation + Data Analysis
        │
        ▼
Week 11
CRS Hardening + Recommendations
        │
        ▼
Week 12
Report + Presentation + Demo
```

---

## 👥 Phân công nhóm

| Member | Responsibility | Main Deliverables |
|---|---|---|
| **Member 1** | Architecture & Integration | Docker, integration, repository |
| **Member 2** | ModSecurity + CRS | Signature WAF, CRS configuration |
| **Member 3** | Machine Learning | Dataset, model, ML-WAF |
| **Member 4** | Bypass Research | Bypass techniques, parser analysis |
| **Member 5** | Automation & Evaluation | Test automation, metrics, visualization |

Các thành viên cần phối hợp và hiểu toàn bộ pipeline để đảm bảo khả năng tích hợp và bảo vệ đồ án.

---

## 🔄 Development Workflow

Repository hiện sử dụng `main` làm branch chính.

Mỗi thành viên phát triển trên feature branch:

```text
main
 │
 ├── feature/docker
 ├── feature/crs
 ├── feature/ml-waf
 ├── feature/bypass
 └── feature/experiments
```

Quy trình:

```text
Feature Branch
      │
      ▼
   Commit
      │
      ▼
Pull Request
      │
      ▼
Review / Test
      │
      ▼
   main
```

### Quy tắc

- Không push trực tiếp vào `main`.
- Mỗi module nên được phát triển trên feature branch.
- Pull Request được review trước khi merge.
- Không commit secret, credential hoặc dữ liệu nhạy cảm.
- Không commit dataset hoặc log chứa thông tin nhạy cảm.
- Experiment phải có cách tái lập rõ ràng.
- Commit message nên mô tả rõ thay đổi.

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

## 🚧 Project Status

**Status: Initial Setup**

### Completed

- [x] Repository created
- [x] Git initialized
- [x] Initial repository structure created
- [x] Research scope defined
- [x] Experimental categories defined
- [x] Initial README created

### In Progress

- [ ] Finalize system architecture
- [ ] Build Docker lab
- [ ] Deploy controlled web application
- [ ] Deploy ModSecurity + OWASP CRS
- [ ] Prepare ML dataset
- [ ] Implement ML-WAF
- [ ] Build automated testing pipeline
- [ ] Conduct baseline experiments
- [ ] Conduct bypass experiments
- [ ] Analyze results
- [ ] CRS hardening
- [ ] Final report
- [ ] Final presentation

---

<p align="center">

**T03 — ML-based WAF & Evasion Techniques**

*Web Security Research Project*

</p>
