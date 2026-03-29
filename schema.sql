-- uilingo / prototypedb — run in phpMyAdmin or mysql CLI if the `user` table is missing or wrong.
-- App maps password_hash in code to MySQL column `password`.
-- If you use password_hash as the column name instead, change app.py User model to:
--   password_hash = db.Column(db.String(255), nullable=False)

CREATE DATABASE IF NOT EXISTS prototypedb
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE prototypedb;

CREATE TABLE IF NOT EXISTS `user` (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(80) NOT NULL,
  password VARCHAR(255) NOT NULL,
  role VARCHAR(20) NOT NULL,
  is_blocked TINYINT(1) NOT NULL DEFAULT 0,
  UNIQUE KEY uq_user_username (username),
  KEY idx_user_username (username)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Add block flag if your table was created earlier without it:
-- ALTER TABLE `user` ADD COLUMN is_blocked TINYINT(1) NOT NULL DEFAULT 0;

-- If you already have a `user` table with a plain `password` column, migrate e.g.:
-- ALTER TABLE `user` ADD COLUMN password_hash VARCHAR(255) NULL AFTER username;
-- (backfill hashes from your app, then DROP COLUMN password;)
