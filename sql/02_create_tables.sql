-- 02_create_tables.sql
-- Create all tables for DAM system

USE dam_system;

-- ===================================================
-- USERS TABLE
-- =====================================================
CREATE TABLE IF NOT EXISTS users (
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
-- ACTIVITY LOGS TABLE
-- =====================================================
CREATE TABLE IF NOT EXISTS activity_logs (
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
-- SECURITY ALERTS TABLE
-- =====================================================
CREATE TABLE IF NOT EXISTS security_alerts (
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
-- IP BLACKLIST TABLE
-- =====================================================
CREATE TABLE IF NOT EXISTS ip_blacklist (
    ip_id INT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) UNIQUE,
    reason TEXT,
    created_at DATETIME,
    expires_at DATETIME,
    INDEX idx_ip (ip_address),
    INDEX idx_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =====================================================
-- COMPLIANCE LOGS TABLE
-- =====================================================
CREATE TABLE IF NOT EXISTS compliance_logs (
    log_id INT AUTO_INCREMENT PRIMARY KEY,
    activity_id INT,
    standard VARCHAR(50),
    finding TEXT,
    status VARCHAR(20),
    created_at DATETIME,
    INDEX idx_standard (standard),
    FOREIGN KEY (activity_id) REFERENCES activity_logs(activity_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Show created tables

SHOW TABLES;
SELECT 'All tables created successfully' AS 'Status';