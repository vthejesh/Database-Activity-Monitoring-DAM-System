-- =====================================================
-- DATABASE ACTIVITY MONITORING (DAM) SYSTEM
-- Schema Definition - CREATE TABLES ONLY
-- =====================================================

-- Drop existing database if exists and create new
DROP DATABASE IF EXISTS dam_system;
CREATE DATABASE dam_system;
USE dam_system;

-- =====================================================
-- 1. USERS TABLE - Store database users
-- =====================================================
CREATE TABLE users (
    user_id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(50) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role ENUM('Admin', 'User', 'Guest') NOT NULL DEFAULT 'User',
    account_status ENUM('Active', 'Inactive') NOT NULL DEFAULT 'Active',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP NULL,
    INDEX idx_username (username),
    INDEX idx_role (role),
    INDEX idx_status (account_status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='User authentication and authorization';

-- =====================================================
-- 2. ACTIVITY_LOGS TABLE - Log all database activities
-- =====================================================
CREATE TABLE activity_logs (
    activity_id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    operation_type ENUM('SELECT', 'INSERT', 'UPDATE', 'DELETE', 'LOGIN', 'LOGOUT') NOT NULL,
    table_name VARCHAR(50) NOT NULL,
    access_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    operation_status ENUM('Success', 'Failed') NOT NULL,
    operation_details TEXT,
    ip_address VARCHAR(45),
    is_suspicious BOOLEAN DEFAULT FALSE,
    suspicious_reasons TEXT,
    INDEX idx_user_id (user_id),
    INDEX idx_operation_type (operation_type),
    INDEX idx_timestamp (access_timestamp),
    INDEX idx_suspicious (is_suspicious),
    INDEX idx_status (operation_status),
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Comprehensive activity logging for security monitoring';

-- =====================================================
-- 3. PRODUCTS TABLE - Sample data table for operations
-- =====================================================
CREATE TABLE products (
    product_id INT PRIMARY KEY AUTO_INCREMENT,
    product_name VARCHAR(100) NOT NULL,
    category VARCHAR(50) NOT NULL,
    price DECIMAL(10, 2) NOT NULL,
    stock_quantity INT NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_category (category),
    INDEX idx_price (price)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Sample product catalog for CRUD operations';

-- =====================================================
-- 4. SECURITY_ALERTS TABLE - Store security alerts
-- =====================================================
CREATE TABLE security_alerts (
    alert_id INT PRIMARY KEY AUTO_INCREMENT,
    activity_id INT NOT NULL,
    alert_type VARCHAR(50) NOT NULL,
    severity ENUM('Low', 'Medium', 'High', 'Critical') NOT NULL,
    alert_message TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_resolved BOOLEAN DEFAULT FALSE,
    resolved_at TIMESTAMP NULL,
    resolved_by INT NULL,
    INDEX idx_activity (activity_id),
    INDEX idx_severity (severity),
    INDEX idx_resolved (is_resolved),
    INDEX idx_created (created_at),
    FOREIGN KEY (activity_id) REFERENCES activity_logs(activity_id) ON DELETE CASCADE,
    FOREIGN KEY (resolved_by) REFERENCES users(user_id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Security alerts with severity levels';

-- =====================================================
-- VIEWS FOR EASY REPORTING
-- =====================================================

-- View: All activities with user details
CREATE VIEW vw_all_activities AS
SELECT 
    al.activity_id,
    u.user_id,
    u.username,
    u.role,
    al.operation_type,
    al.table_name,
    al.access_timestamp,
    al.operation_status,
    al.operation_details,
    al.ip_address,
    al.is_suspicious,
    al.suspicious_reasons
FROM activity_logs al
LEFT JOIN users u ON al.user_id = u.user_id;

-- View: Suspicious activities only
CREATE VIEW vw_suspicious_activities AS
SELECT * FROM vw_all_activities
WHERE is_suspicious = TRUE;

-- View: Activity summary by user
CREATE VIEW vw_user_activity_summary AS
SELECT 
    u.user_id,
    u.username,
    u.role,
    COUNT(al.activity_id) as total_activities,
    SUM(CASE WHEN al.is_suspicious THEN 1 ELSE 0 END) as suspicious_count,
    SUM(CASE WHEN al.operation_status = 'Failed' THEN 1 ELSE 0 END) as failed_count,
    SUM(CASE WHEN al.operation_status = 'Success' THEN 1 ELSE 0 END) as success_count,
    MAX(al.access_timestamp) as last_activity
FROM users u
LEFT JOIN activity_logs al ON u.user_id = al.user_id
GROUP BY u.user_id, u.username, u.role;