-- =============================================================================
-- T03 — docker/db/init/01-schema.sql
-- Owner: Hoàng Minh Hiếu. Track trong git, chạy 1 lần khi `db` khởi tạo.
-- Schema tối thiểu cho web-app lab: waf_lab.users
-- =============================================================================
CREATE DATABASE IF NOT EXISTS waf_lab CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE waf_lab;

CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(64) NOT NULL UNIQUE,
  password VARCHAR(128) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
