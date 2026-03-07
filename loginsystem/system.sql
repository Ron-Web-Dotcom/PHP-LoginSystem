-- PHP-LoginSystem — full database schema
-- Import with: mysql -u root -p system < system.sql
--
-- Server version: 5.7+
-- Charset: utf8mb4

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
SET AUTOCOMMIT = 0;
START TRANSACTION;
SET time_zone = "+00:00";
SET NAMES utf8mb4;

-- --------------------------------------------------------
-- Database: `system`
-- --------------------------------------------------------
CREATE DATABASE IF NOT EXISTS `system`
  DEFAULT CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE `system`;

-- --------------------------------------------------------
-- Table: tbl_signup  (core user accounts)
-- --------------------------------------------------------
DROP TABLE IF EXISTS `tbl_signup`;
CREATE TABLE `tbl_signup` (
  `email`        VARCHAR(255) NOT NULL,
  `password`     VARCHAR(255) NOT NULL,
  `totp_secret`  VARCHAR(32)  NULL        DEFAULT NULL,
  `totp_enabled` TINYINT(1)   NOT NULL    DEFAULT 0,
  `is_admin`     TINYINT(1)   NOT NULL    DEFAULT 0,
  `status`       VARCHAR(10)  NOT NULL    DEFAULT 'active',
  `role`         VARCHAR(20)  NOT NULL    DEFAULT 'user',
  `onboarded`    TINYINT(1)   NOT NULL    DEFAULT 0,
  PRIMARY KEY (`email`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------
-- Table: tbl_login_attempts  (brute-force lockout tracking)
-- --------------------------------------------------------
DROP TABLE IF EXISTS `tbl_login_attempts`;
CREATE TABLE `tbl_login_attempts` (
  `id`           INT          NOT NULL AUTO_INCREMENT,
  `email`        VARCHAR(255) NOT NULL,
  `ip`           VARCHAR(45)  NOT NULL,
  `attempt_time` DATETIME     NOT NULL,
  PRIMARY KEY (`id`),
  INDEX `idx_email_time` (`email`, `attempt_time`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------
-- Table: tbl_session_log  (login history)
-- --------------------------------------------------------
DROP TABLE IF EXISTS `tbl_session_log`;
CREATE TABLE `tbl_session_log` (
  `id`         INT          NOT NULL AUTO_INCREMENT,
  `email`      VARCHAR(255) NOT NULL,
  `ip`         VARCHAR(45)  NOT NULL,
  `login_time` DATETIME     NOT NULL,
  PRIMARY KEY (`id`),
  INDEX `idx_email_time` (`email`, `login_time`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------
-- Table: tbl_remember_tokens  (persistent "remember me" sessions)
-- --------------------------------------------------------
DROP TABLE IF EXISTS `tbl_remember_tokens`;
CREATE TABLE `tbl_remember_tokens` (
  `id`         INT          NOT NULL AUTO_INCREMENT,
  `email`      VARCHAR(255) NOT NULL,
  `token_hash` VARCHAR(64)  NOT NULL,
  `expires_at` DATETIME     NOT NULL,
  `created_at` DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  INDEX `idx_email` (`email`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------
-- Table: tbl_password_resets  (password reset tokens)
-- --------------------------------------------------------
DROP TABLE IF EXISTS `tbl_password_resets`;
CREATE TABLE `tbl_password_resets` (
  `id`         INT          NOT NULL AUTO_INCREMENT,
  `email`      VARCHAR(255) NOT NULL,
  `token_hash` VARCHAR(64)  NOT NULL,
  `expires_at` DATETIME     NOT NULL,
  PRIMARY KEY (`id`),
  INDEX `idx_token` (`token_hash`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------
-- Table: tbl_ip_blocklist  (admin-managed IP bans)
-- --------------------------------------------------------
DROP TABLE IF EXISTS `tbl_ip_blocklist`;
CREATE TABLE `tbl_ip_blocklist` (
  `id`         INT          NOT NULL AUTO_INCREMENT,
  `ip`         VARCHAR(45)  NOT NULL,
  `reason`     VARCHAR(255) NULL,
  `blocked_at` DATETIME     NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_ip` (`ip`),
  INDEX `idx_ip` (`ip`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------
-- Table: tbl_audit_log  (security event history)
-- --------------------------------------------------------
DROP TABLE IF EXISTS `tbl_audit_log`;
CREATE TABLE `tbl_audit_log` (
  `id`         INT          NOT NULL AUTO_INCREMENT,
  `email`      VARCHAR(255) NOT NULL,
  `event`      VARCHAR(50)  NOT NULL,
  `detail`     TEXT         NULL,
  `ip`         VARCHAR(45)  NULL,
  `created_at` DATETIME     NOT NULL,
  PRIMARY KEY (`id`),
  INDEX `idx_email`   (`email`),
  INDEX `idx_created` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------
-- Table: tbl_password_history  (prevent password reuse)
-- --------------------------------------------------------
DROP TABLE IF EXISTS `tbl_password_history`;
CREATE TABLE `tbl_password_history` (
  `id`            INT          NOT NULL AUTO_INCREMENT,
  `email`         VARCHAR(255) NOT NULL,
  `password_hash` VARCHAR(255) NOT NULL,
  `changed_at`    DATETIME     NOT NULL,
  PRIMARY KEY (`id`),
  INDEX `idx_email` (`email`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------
-- Table: tbl_magic_links  (passwordless login tokens)
-- --------------------------------------------------------
DROP TABLE IF EXISTS `tbl_magic_links`;
CREATE TABLE `tbl_magic_links` (
  `id`         INT          NOT NULL AUTO_INCREMENT,
  `email`      VARCHAR(255) NOT NULL,
  `token_hash` VARCHAR(64)  NOT NULL,
  `expires_at` DATETIME     NOT NULL,
  `used`       TINYINT(1)   NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  INDEX `idx_token` (`token_hash`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------
-- Table: tbl_backup_codes  (2FA backup codes)
-- --------------------------------------------------------
DROP TABLE IF EXISTS `tbl_backup_codes`;
CREATE TABLE `tbl_backup_codes` (
  `id`         INT          NOT NULL AUTO_INCREMENT,
  `email`      VARCHAR(255) NOT NULL,
  `code_hash`  VARCHAR(64)  NOT NULL,
  `used_at`    DATETIME     NULL,
  `created_at` DATETIME     NOT NULL,
  PRIMARY KEY (`id`),
  INDEX `idx_email` (`email`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------
-- Table: tbl_notifications  (in-app user notifications)
-- --------------------------------------------------------
DROP TABLE IF EXISTS `tbl_notifications`;
CREATE TABLE `tbl_notifications` (
  `id`         INT          NOT NULL AUTO_INCREMENT,
  `email`      VARCHAR(255) NOT NULL,
  `message`    TEXT         NOT NULL,
  `type`       VARCHAR(20)  NOT NULL DEFAULT 'info',
  `is_read`    TINYINT(1)   NOT NULL DEFAULT 0,
  `created_at` DATETIME     NOT NULL,
  PRIMARY KEY (`id`),
  INDEX `idx_email_read` (`email`, `is_read`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

COMMIT;
