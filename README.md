# T03 — ML-based WAF & Evasion Techniques

> **Nghiên cứu WAF học máy và kỹ thuật né tránh: tái lập tấn công đối kháng trên môi trường phòng thí nghiệm**

<p align="center">

![Status](https://img.shields.io/badge/status-in%20development-yellow)
![Project](https://img.shields.io/badge/project-T03-blue)
![Security](https://img.shields.io/badge/domain-Web%20Security-red)
![WAF](https://img.shields.io/badge/WAF-ModSecurity%20%7C%20ML-orange)
![Environment](https://img.shields.io/badge/environment-Docker-blue)
![License](https://img.shields.io/badge/license-Academic-lightgrey)

</p>

---

## 📌 Giới thiệu

**T03 — ML-based WAF & Evasion Techniques** là đồ án nghiên cứu về **Web Application Firewall (WAF)**, tập trung vào việc tìm hiểu khả năng phát hiện tấn công của hai hướng tiếp cận:

1. **Signature-based WAF** — sử dụng ModSecurity kết hợp OWASP Core Rule Set (CRS).
2. **Machine-Learning-based WAF** — WAF sử dụng mô hình học máy để phân loại request.

Đồ án xây dựng một **môi trường lab hoàn toàn local và được kiểm soát**, sau đó tái lập một số kỹ thuật né tránh WAF đã được nghiên cứu/công bố.

Mục tiêu không chỉ là xác định một payload có vượt qua WAF hay không, mà quan trọng hơn là **giải thích cơ chế gốc khiến WAF bị vượt qua**, đặc biệt là các trường hợp có sự khác biệt trong cách WAF và ứng dụng phân tích (parsing) request.

---

# 🎯 Mục tiêu đồ án

## Mục tiêu chính

Đồ án hướng tới việc trả lời các câu hỏi:

- WAF signature-based và ML-based phát hiện request độc hại như thế nào?
- Vì sao một request SQL Injection có thể bị WAF phát hiện ở dạng này nhưng lại vượt qua khi được biến đổi?
- Các kỹ thuật mutation/encoding có ảnh hưởng như thế nào đến khả năng phát hiện?
- Sự khác biệt giữa parser của WAF và parser của ứng dụng có thể dẫn đến bypass như thế nào?
- WAF signature-based và ML-based phản ứng khác nhau ra sao trước cùng một tập biến thể?
- Việc tăng mức **Paranoia Level** của OWASP CRS ảnh hưởng như thế nào đến detection và false positive?
- Có thể đưa ra những khuyến nghị cấu hình nào dựa trên kết quả thực nghiệm?

---

# 🔬 Phạm vi nghiên cứu

## WAF được nghiên cứu

### 1. Signature-based WAF

Sử dụng:

- ModSecurity
- OWASP Core Rule Set (CRS)

Đây là baseline chính của đồ án.

### 2. Machine-Learning-based WAF

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

Mô hình cụ thể sẽ được lựa chọn sau giai đoạn baseline và đánh giá dataset.

---

# 🧪 Các kỹ thuật bypass nghiên cứu

Đồ án tập trung vào bốn nhóm kỹ thuật:

| # | Kỹ thuật | Mục đích nghiên cứu |
|---|---|---|
| 1 | HTTP Parameter Pollution / Fragmentation | Nghiên cứu cách xử lý parameter khác nhau |
| 2 | Double Encoding | Nghiên cứu vấn đề canonicalization / decoding |
| 3 | Case Variation + SQL Comment | Nghiên cứu signature evasion |
| 4 | Parsing Discrepancy | Nghiên cứu sự khác biệt giữa WAF parser và application parser |

> **Lưu ý:** Các thử nghiệm chỉ được thực hiện trên hệ thống lab do nhóm kiểm soát. Không sử dụng đồ án để kiểm thử hoặc tấn công hệ thống production, WAF thương mại hoặc hệ thống của bên thứ ba khi chưa được phép.

---

# 🏗️ Kiến trúc hệ thống dự kiến

## Tổng quan

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

# 🔬 Experimental Pipeline

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

Đối với mỗi bypass, nhóm sẽ không chỉ ghi nhận kết quả `Blocked/Allowed` mà còn phân tích:

- WAF nhìn thấy request như thế nào?
- Application nhìn thấy request như thế nào?
- Request có bị decode/canonicalize hay không?
- Parser nào xử lý khác?
- Signature hoặc ML model đã bỏ sót đặc trưng nào?
- Vì sao payload vẫn giữ được semantic sau khi biến đổi?

---

# 📊 Phương pháp đánh giá

## 1. Detection Rate

Tỷ lệ request độc hại được WAF phát hiện:

```text
Detection Rate =
Detected Malicious Requests
--------------------------- × 100%
Total Malicious Requests
```

## 2. Bypass Rate

Tỷ lệ request độc hại vượt qua WAF:

```text
Bypass Rate =
Successful Bypass Requests
-------------------------- × 100%
Total Malicious Requests
```

## 3. False Positive Rate

Tỷ lệ request hợp lệ nhưng bị WAF chặn:

```text
False Positive Rate =
Benign Requests Blocked
----------------------- × 100%
Total Benign Requests
```

## 4. Machine Learning Metrics

Đối với ML-WAF sẽ đánh giá thêm:

- Accuracy
- Precision
- Recall
- F1-score
- False Positive Rate
- False Negative Rate

---

# 📋 Experimental Matrix

Kết quả cuối cùng dự kiến được tổng hợp theo bảng:

| Technique | Total Tests | CRS Blocked | CRS Bypass | ML Blocked | ML Bypass |
|---|---:|---:|---:|---:|---:|
| Baseline | TBD | TBD | TBD | TBD | TBD |
| HPP / Fragmentation | TBD | TBD | TBD | TBD | TBD |
| Double Encoding | TBD | TBD | TBD | TBD | TBD |
| Case + SQL Comment | TBD | TBD | TBD | TBD | TBD |
| Parsing Discrepancy | TBD | TBD | TBD | TBD | TBD |

> `TBD` sẽ được thay thế bằng kết quả thực nghiệm sau khi hoàn thành test.

---

# 🛡️ OWASP CRS Paranoia Level

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
- Số lượng rule được kích hoạt
- Các loại request bị ảnh hưởng

Mục tiêu là xác định sự cân bằng giữa:

```text
Security
    ↕
False Positive
```

và đưa ra khuyến nghị cấu hình dựa trên **kết quả thực nghiệm**, thay vì chỉ dựa trên lý thuyết.

---

# 📁 Cấu trúc repository

```text
WAF-ML-Bypass/
│
├── dataset/
│   ├── raw/
│   ├── processed/
│   └── bypass/
│       ├── hpp/
│       ├── double-encoding/
│       ├── case-comment/
│       └── parsing-discrepancy/
│
├── docker/
│   ├── waf-crs/
│   ├── waf-ml/
│   └── web-app/
│
├── docs/
│
├── experiments/
│   ├── baseline/
│   ├── hpp/
│   ├── double-encoding/
│   ├── case-comment/
│   └── parsing-discrepancy/
│
├── logs/
│   ├── waf/
│   └── application/
│
├── report/
│
├── results/
│   ├── raw/
│   ├── tables/
│   └── graphs/
│
├── scripts/
│
├── waf-crs/
├── waf-ml/
└── web-app/
```

## Vai trò các thư mục

| Directory | Mục đích |
|---|---|
| `dataset/` | Dataset dùng cho ML và các test case |
| `dataset/raw/` | Dữ liệu gốc |
| `dataset/processed/` | Dataset sau preprocessing |
| `dataset/bypass/` | Test cases theo từng kỹ thuật bypass |
| `docker/` | Docker configuration cho các service |
| `waf-crs/` | ModSecurity + OWASP CRS |
| `waf-ml/` | ML-based WAF |
| `web-app/` | Web application mục tiêu trong lab |
| `experiments/` | Tổ chức các experiment |
| `scripts/` | Script tự động hóa |
| `logs/` | Log từ WAF và application |
| `results/` | Kết quả thực nghiệm |
| `docs/` | Tài liệu kỹ thuật và nghiên cứu |
| `report/` | Tài liệu phục vụ báo cáo cuối kỳ |

---

# 🧰 Công nghệ & công cụ

## Core

- Docker
- Docker Compose
- ModSecurity
- OWASP CRS
- Python
- Git / GitHub

## Security Testing

- wafw00f
- sqlmap
- WAF-A-MoLE
- Custom testing scripts

## Machine Learning

Dự kiến sử dụng Python ecosystem:

- Python
- NumPy
- Pandas
- scikit-learn

Mô hình cụ thể sẽ được lựa chọn sau khi đánh giá dataset và baseline.

## Visualization

Có thể sử dụng:

- Matplotlib
- Pandas
- Jupyter Notebook

---

# 📚 Tài liệu tham khảo chính

### WAF-A-MoLE

Demetrio et al. (2020).

> *WAF-A-MoLE: ...*

Proceedings of the 35th Annual ACM Symposium on Applied Computing.

DOI:

`10.1145/3341105.3373962`

---

### AdvSQLi

Qu et al. (2024).

> *AdvSQLi: Generating Adversarial SQL Injections Against Real-World WAF-as-a-Service.*

IEEE Transactions on Information Forensics and Security.

DOI:

`10.1109/TIFS.2024.3350911`

---

### WAFBooster

Wu et al. (2025).

> *WAFBooster: Automatic Boosting of WAF Security Against Mutated Malicious Payloads.*

IEEE Transactions on Dependable and Secure Computing.

DOI:

`10.1109/TDSC.2024.3429271`

---

### Signature-based vs Machine-Learning-based WAF

Applebaum et al. (2021).

> *Signature-based and Machine-Learning-based Web Application Firewalls: A Short Survey.*

Procedia Computer Science.

DOI:

`10.1016/j.procs.2021.05.105`

---

### Deep Learning WAF

Dawadi et al. (2023).

> *Deep Learning Technique-Enabled Web Application Firewall for the Detection of Web Attacks.*

Sensors.

DOI:

`10.3390/s23042073`

---

### WAFFLED

Akhavani et al. (2025).

> *WAFFLED: Exploiting Parsing Discrepancies to Bypass Web Application Firewalls.*

2025 IEEE Annual Computer Security Applications Conference (ACSAC).

DOI:

`10.1109/ACSAC67867.2025.00062`

---

# 🗓️ Project Roadmap

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

# 👥 Phân công nhóm

| Member | Responsibility | Main Deliverables |
|---|---|---|
| **Member 1** | Architecture & Integration | Docker, integration, repository |
| **Member 2** | ModSecurity + CRS | Signature WAF, CRS configuration |
| **Member 3** | Machine Learning | Dataset, model, ML-WAF |
| **Member 4** | Bypass Research | Bypass techniques, parser analysis |
| **Member 5** | Automation & Evaluation | Test automation, metrics, visualization |

> Thành viên vẫn cần hiểu toàn bộ pipeline của hệ thống để đảm bảo khả năng phối hợp và bảo vệ đồ án.

---

# 🔄 Development Workflow

Repository sử dụng Git để quản lý quá trình phát triển.

```text
main
  │
  └── dev
       │
       ├── feature/docker
       ├── feature/crs
       ├── feature/ml-waf
       ├── feature/bypass
       └── feature/experiments
```

### Quy tắc cơ bản

- Không push trực tiếp vào `main`.
- Mỗi module phát triển trên branch riêng.
- Pull Request được review trước khi merge.
- Không commit secret, credential hoặc dữ liệu nhạy cảm.
- Các experiment phải có cách tái lập rõ ràng.
- Kết quả thực nghiệm phải lưu cùng metadata cần thiết.

---

# 🔐 Ethical & Safety Scope

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

# 🎓 Expected Deliverables

Khi hoàn thành, project dự kiến cung cấp:

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

Script tự động:

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

Dataset được tổ chức thành:

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

Báo cáo mô tả:

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

# 📌 Research Questions

Đồ án tập trung vào các câu hỏi nghiên cứu:

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

# 🚧 Current Status

> **Status: Initial Setup**

Completed:

- [x] Repository created
- [x] Git initialized
- [x] Initial repository structure created
- [x] Research scope defined
- [x] Experimental categories defined

In progress:

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

# 📄 Project Status

This repository is currently under active development as part of a university cybersecurity research project.

The experimental results shown in the repository will be updated as experiments are completed.

---

<p align="center">

**T03 — ML-based WAF & Evasion Techniques**

*Web Security Research Project*

</p>
