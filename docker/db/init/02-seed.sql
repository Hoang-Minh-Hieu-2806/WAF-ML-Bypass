-- =============================================================================
-- T03 — docker/db/init/02-seed.sql
-- Data FAKE cho lab only. Không dùng credential thật.
-- =============================================================================
USE waf_lab;

INSERT INTO users (username, password) VALUES
  ('alice', 'alice123'),
  ('bob', 'bob123'),
  ('admin', 'admin123'),
  ('test', 'test123'),
  ('user1', 'password1')
ON DUPLICATE KEY UPDATE password = VALUES(password);
