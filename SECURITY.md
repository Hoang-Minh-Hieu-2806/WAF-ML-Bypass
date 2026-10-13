# Security Policy

## Phạm vi nghiên cứu có trách nhiệm

Đây là đồ án **nghiên cứu phòng thủ** thực hiện hoàn toàn trên **lab local do nhóm kiểm soát**
(Web App + MySQL + ModSecurity/CRS + ML-WAF chạy bằng Docker trên máy cá nhân).

- Chỉ kiểm thử trên lab local, không kiểm thử WAF production của bên thứ ba.
- Không sử dụng payload trong repo để tấn công hệ thống không được cấp phép.
- Không thu thập dữ liệu cá nhân, không đưa credential/secret vào repository.
- `.env`, `mysql-data/`, `*.log`, `*.pkl`, dataset thô đã được `.gitignore` chặn.

## Báo cáo lỗ hổng

Nếu phát hiện thông tin nhạy cảm bị commit nhầm (secret, log chứa dữ liệu thật),
vui lòng báo qua GitHub Issues và không công khai nội dung nhạy cảm.
Nhóm sẽ gỡ bỏ và xoay vòng credential liên quan.
