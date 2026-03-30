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

CREATE TABLE IF NOT EXISTS activity_upload (
  id INT AUTO_INCREMENT PRIMARY KEY,
  lecturer_id INT NOT NULL,
  title VARCHAR(200) NOT NULL,
  stored_filename VARCHAR(255) NOT NULL,
  original_filename VARCHAR(255) NOT NULL,
  created_at DATETIME NOT NULL,
  KEY idx_activity_lecturer (lecturer_id),
  CONSTRAINT fk_activity_lecturer FOREIGN KEY (lecturer_id) REFERENCES user (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS grade_entry (
  id INT AUTO_INCREMENT PRIMARY KEY,
  lecturer_id INT NOT NULL,
  student_id INT NOT NULL,
  assignment_name VARCHAR(200) NOT NULL,
  score FLOAT NOT NULL,
  max_score FLOAT NOT NULL DEFAULT 100,
  created_at DATETIME NOT NULL,
  UNIQUE KEY uq_grade_lecturer_student_assignment (lecturer_id, student_id, assignment_name),
  KEY idx_grade_lecturer (lecturer_id),
  KEY idx_grade_student (student_id),
  CONSTRAINT fk_grade_lecturer FOREIGN KEY (lecturer_id) REFERENCES user (id) ON DELETE CASCADE,
  CONSTRAINT fk_grade_student FOREIGN KEY (student_id) REFERENCES user (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS glossary_entry (
  id INT AUTO_INCREMENT PRIMARY KEY,
  lecturer_id INT NOT NULL,
  term VARCHAR(255) NOT NULL,
  definition TEXT NOT NULL,
  created_at DATETIME NOT NULL,
  UNIQUE KEY uq_glossary_lecturer_term (lecturer_id, term),
  KEY idx_glossary_lecturer (lecturer_id),
  CONSTRAINT fk_glossary_lecturer FOREIGN KEY (lecturer_id) REFERENCES user (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS student_message (
  id INT AUTO_INCREMENT PRIMARY KEY,
  sender_id INT NOT NULL,
  recipient_id INT NOT NULL,
  message_text TEXT NOT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY idx_student_message_sender (sender_id),
  KEY idx_student_message_recipient (recipient_id),
  KEY idx_student_message_created (created_at),
  CONSTRAINT fk_student_message_sender FOREIGN KEY (sender_id) REFERENCES user (id) ON DELETE CASCADE,
  CONSTRAINT fk_student_message_recipient FOREIGN KEY (recipient_id) REFERENCES user (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
