CREATE DATABASE IF NOT EXISTS gloriam_school
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE gloriam_school;

CREATE TABLE IF NOT EXISTS admins (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(100) NOT NULL UNIQUE,
  email VARCHAR(255) NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS contact_messages (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  full_name VARCHAR(160) NOT NULL,
  phone_number VARCHAR(40) NOT NULL,
  email VARCHAR(255) NOT NULL,
  message TEXT NOT NULL,
  submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS users (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  full_name VARCHAR(160) NOT NULL,
  email VARCHAR(255) NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS school_registrations (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  user_id BIGINT NOT NULL,
  student_name VARCHAR(160) NOT NULL,
  level ENUM('Nursery', 'Primary', 'Secondary') NOT NULL,
  parent_phone VARCHAR(40) NOT NULL,
  message TEXT NOT NULL,
  admin_reply TEXT NULL,
  status ENUM('pending', 'replied') DEFAULT 'pending',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  CONSTRAINT fk_reg_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

INSERT INTO admins (username, email, password_hash)
SELECT
  'admin',
  'gloriaminternationalschool@gmail.com',
  '$2b$10$F5K5jD7pAT36nLQd.kPvluPu4.shDawemfcODpot1juvgXIRCbDFq'
WHERE NOT EXISTS (
  SELECT 1 FROM admins WHERE username = 'admin'
);
