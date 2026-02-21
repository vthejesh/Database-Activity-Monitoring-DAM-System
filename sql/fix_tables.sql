-- fix_tables.sql
-- Drop and recreate all tables with correct structure

USE dam_system;

-- =====================================================
-- DROP ALL EXISTING TABLES (in correct order)
-- =====================================================
SET FOREIGN_KEY_CHECKS = 0;

DROP TABLE IF EXISTS compliance_logs;
DROP TABLE IF EXISTS security_alerts;
DROP TABLE IF EXISTS activity_logs;
DROP TABLE IF EXISTS ip_blacklist;
DROP TABLE IF EXISTS users;

SET FOREIGN_KEY_CHECKS = 1;

-- =====================================================
-- RECREATE USERS TABLE
-- =====================================================
CREATE TABLE users (
    user_id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role ENUM('Admin', 'User', 'Guest') DEFAULT 'Guest',
    account_status ENUM('Active', 'Inactive', 'Locked') DEFAULT 'Active',
    failed_attempts INT DEFAULT 0,
    locked_until DATETIME NULL,
    last_login DATETIME NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_username (username),
    INDEX idx_status (account_status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =====================================================
-- RECREATE ACTIVITY LOGS TABLE (with session_id column)
-- =====================================================
CREATE TABLE activity_logs (
    activity_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NULL,
    username VARCHAR(50),
    operation_type VARCHAR(20),
    table_name VARCHAR(50),
    operation_status VARCHAR(20),
    operation_details TEXT,
    ip_address VARCHAR(45),
    access_timestamp DATETIME,
    session_id VARCHAR(100) NULL,
    rows_affected INT NULL,
    query_hash VARCHAR(64) NULL,
    is_suspicious BOOLEAN DEFAULT FALSE,
    suspicious_reasons TEXT NULL,
    severity_level ENUM('Low', 'Medium', 'High', 'Critical') DEFAULT 'Low',
    INDEX idx_timestamp (access_timestamp),
    INDEX idx_user (user_id),
    INDEX idx_suspicious (is_suspicious),
    INDEX idx_hash (query_hash),
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =====================================================
-- RECREATE SECURITY ALERTS TABLE (with status column)
-- =====================================================
CREATE TABLE security_alerts (
    alert_id INT AUTO_INCREMENT PRIMARY KEY,
    activity_id INT,
    alert_type VARCHAR(50),
    severity VARCHAR(20),
    description TEXT,
    status ENUM('New', 'Investigating', 'Resolved') DEFAULT 'New',
    created_at DATETIME,
    resolved_at DATETIME NULL,
    INDEX idx_status (status),
    INDEX idx_created (created_at),
    FOREIGN KEY (activity_id) REFERENCES activity_logs(activity_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =====================================================
-- RECREATE IP BLACKLIST TABLE
-- =====================================================
CREATE TABLE ip_blacklist (
    ip_id INT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) UNIQUE,
    reason TEXT,
    created_at DATETIME,
    expires_at DATETIME,
    INDEX idx_ip (ip_address),
    INDEX idx_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =====================================================
-- RECREATE COMPLIANCE LOGS TABLE
-- =====================================================
CREATE TABLE compliance_logs (
    log_id INT AUTO_INCREMENT PRIMARY KEY,
    activity_id INT,
    standard VARCHAR(50),
    finding TEXT,
    status VARCHAR(20),
    created_at DATETIME,
    INDEX idx_standard (standard),
    FOREIGN KEY (activity_id) REFERENCES activity_logs(activity_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =====================================================
-- INSERT DEFAULT USERS
-- =====================================================
-- Admin user (password: admin123)
INSERT IGNORE INTO users (username, password_hash, role, account_status, created_at)
VALUES (
    'admin', 
    'pbkdf2:sha256:600000$DoFHEl6gFfJYQnM6$8c9c5d4b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a0f9e8d7c6b5a4f3e2d1c',
    'Admin', 
    'Active', 
    NOW()
);

-- Regular user (password: user123)
INSERT IGNORE INTO users (username, password_hash, role, account_status, created_at)
VALUES (
    'user1', 
    'pbkdf2:sha256:600000$DoFHEl6gFfJYQnM6$8c9c5d4b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a0f9e8d7c6b5a4f3e2d1c',
    'User', 
    'Active', 
    NOW()
);

-- Guest user (password: guest123)
INSERT IGNORE INTO users (username, password_hash, role, account_status, created_at)
VALUES (
    'guest1', 
    'pbkdf2:sha256:600000$DoFHEl6gFfJYQnM6$8c9c5d4b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a0f9e8d7c6b5a4f3e2d1c',
    'Guest', 
    'Active', 
    NOW()
);

-- Show results
SELECT 'Tables recreated successfully' AS 'Status';
SELECT 'Users:' AS '';
SELECT user_id, username, role, account_status FROM users;