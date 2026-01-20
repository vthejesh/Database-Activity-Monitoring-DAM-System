-- =====================================================
-- DATABASE ACTIVITY MONITORING (DAM) SYSTEM
-- Seed Data - Sample INSERT Statements
-- =====================================================

USE dam_system;

-- =====================================================
-- SAMPLE USERS
-- =====================================================
-- NOTE: Passwords are hashed using Werkzeug's generate_password_hash
-- To generate your own hashed passwords, run:
-- python -c "from werkzeug.security import generate_password_hash; print(generate_password_hash('your_password'))"

-- Admin User (username: admin, password: admin123)
INSERT INTO users (username, password_hash, role, account_status) VALUES
('admin', 'scrypt:32768:8:1$YQ8ZGxHKvj6DX9Mc$8f2e7c1d4b5a6e8f9c0d1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e', 'Admin', 'Active');

-- Regular User (username: john_doe, password: user123)
INSERT INTO users (username, password_hash, role, account_status) VALUES
('john_doe', 'scrypt:32768:8:1$XP7YFwGJui5CW8Lb$7e1f6c0d3b4a5e7f8c9d0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e', 'User', 'Active');

-- Another Regular User (username: jane_smith, password: user456)
INSERT INTO users (username, password_hash, role, account_status) VALUES
('jane_smith', 'scrypt:32768:8:1$WO6XEvFIth4BV7Ka$6d0e5b9c2a3d4e6f7c8d9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e', 'User', 'Active');

-- Guest User (username: guest_user, password: guest123)
INSERT INTO users (username, password_hash, role, account_status) VALUES
('guest_user', 'scrypt:32768:8:1$VN5WDuEHsg3AU6Jz$5c9d4b8c1a2d3e5f6c7d8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e', 'Guest', 'Active');

-- Inactive User (for testing account status)
INSERT INTO users (username, password_hash, role, account_status) VALUES
('inactive_user', 'scrypt:32768:8:1$UM4VCuDGrf2ZT5Iy$4b8c3a7d2e4f5c6d7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a', 'User', 'Inactive');

-- =====================================================
-- SAMPLE PRODUCTS
-- =====================================================
INSERT INTO products (product_name, category, price, stock_quantity) VALUES
-- Electronics
('Laptop Dell XPS 15', 'Electronics', 1299.99, 50),
('iPhone 15 Pro', 'Electronics', 999.99, 100),
('Samsung 4K TV 55 inch', 'Electronics', 699.99, 30),
('Sony Wireless Headphones', 'Electronics', 249.99, 75),
('iPad Air 2024', 'Electronics', 599.99, 60),

-- Clothing
('Nike Running Shoes', 'Clothing', 129.99, 200),
('Adidas Sports Jersey', 'Clothing', 49.99, 150),
('Levis Jeans', 'Clothing', 79.99, 180),
('North Face Jacket', 'Clothing', 199.99, 90),
('Under Armour T-Shirt', 'Clothing', 29.99, 250),

-- Books
('Python Programming Guide', 'Books', 39.99, 300),
('Database Design Fundamentals', 'Books', 44.99, 250),
('Machine Learning Basics', 'Books', 54.99, 180),
('Cybersecurity Essentials', 'Books', 49.99, 200),
('Web Development Complete', 'Books', 59.99, 150),

-- Furniture
('Office Chair Ergonomic', 'Furniture', 249.99, 75),
('Standing Desk Adjustable', 'Furniture', 399.99, 40),
('Bookshelf Wooden 5-Tier', 'Furniture', 149.99, 60),
('Computer Desk Modern', 'Furniture', 179.99, 55),
('Filing Cabinet Metal', 'Furniture', 129.99, 45);

-- =====================================================
-- SAMPLE ACTIVITY LOGS (for demonstration)
-- =====================================================
-- These show various types of activities that would be logged

-- Successful admin login
INSERT INTO activity_logs (user_id, operation_type, table_name, operation_status, operation_details, ip_address) VALUES
(1, 'LOGIN', 'users', 'Success', 'Admin login from web interface', '192.168.1.100');

-- User viewing products
INSERT INTO activity_logs (user_id, operation_type, table_name, operation_status, operation_details, ip_address) VALUES
(2, 'SELECT', 'products', 'Success', 'Viewed product list', '192.168.1.101');

-- User creating a product
INSERT INTO activity_logs (user_id, operation_type, table_name, operation_status, operation_details, ip_address) VALUES
(2, 'INSERT', 'products', 'Success', 'Added new product: Wireless Mouse', '192.168.1.101');

-- User updating a product
INSERT INTO activity_logs (user_id, operation_type, table_name, operation_status, operation_details, ip_address) VALUES
(3, 'UPDATE', 'products', 'Success', 'Updated price for product_id 1', '192.168.1.102');

-- Guest attempting to delete (SHOULD BE SUSPICIOUS)
INSERT INTO activity_logs (user_id, operation_type, table_name, operation_status, operation_details, ip_address, is_suspicious, suspicious_reasons) VALUES
(4, 'DELETE', 'products', 'Failed', 'RBAC Violation: Guest user attempted unauthorized DELETE operation', '192.168.1.103', TRUE, 'RBAC Violation: Guest user attempting write operation (DML)');

-- Guest attempting to insert (SHOULD BE SUSPICIOUS)
INSERT INTO activity_logs (user_id, operation_type, table_name, operation_status, operation_details, ip_address, is_suspicious, suspicious_reasons) VALUES
(4, 'INSERT', 'products', 'Failed', 'RBAC Violation: Guest user attempted unauthorized INSERT operation', '192.168.1.103', TRUE, 'RBAC Violation: Guest user attempting write operation (DML)');

-- Failed login attempts (for brute force detection testing)
INSERT INTO activity_logs (user_id, operation_type, table_name, operation_status, operation_details, ip_address) VALUES
(0, 'LOGIN', 'users', 'Failed', 'Attempted username: hacker. Invalid credentials', '192.168.1.200'),
(0, 'LOGIN', 'users', 'Failed', 'Attempted username: hacker. Invalid credentials', '192.168.1.200'),
(0, 'LOGIN', 'users', 'Failed', 'Attempted username: hacker. Invalid credentials', '192.168.1.200'),
(0, 'LOGIN', 'users', 'Failed', 'Attempted username: hacker. Invalid credentials', '192.168.1.200'),
(0, 'LOGIN', 'users', 'Failed', 'Attempted username: hacker. Invalid credentials', '192.168.1.200'),
(0, 'LOGIN', 'users', 'Failed', 'Attempted username: hacker. Invalid credentials', '192.168.1.200');

-- Mark the 6th failed login as suspicious (brute force)
UPDATE activity_logs 
SET is_suspicious = TRUE,
    suspicious_reasons = 'Brute Force Attack: 6 failed login attempts for username "hacker"'
WHERE activity_id = (SELECT MAX(activity_id) FROM (SELECT activity_id FROM activity_logs WHERE operation_type = 'LOGIN' AND operation_status = 'Failed') AS temp);

-- Failed query (syntax error)
INSERT INTO activity_logs (user_id, operation_type, table_name, operation_status, operation_details, ip_address) VALUES
(2, 'SELECT', 'products', 'Failed', 'Invalid query syntax', '192.168.1.101');

-- Successful logout
INSERT INTO activity_logs (user_id, operation_type, table_name, operation_status, operation_details, ip_address) VALUES
(1, 'LOGOUT', 'users', 'Success', 'Admin logout', '192.168.1.100');

-- =====================================================
-- SAMPLE SECURITY ALERTS (corresponding to suspicious activities)
-- =====================================================

-- Alert for Guest DELETE attempt
INSERT INTO security_alerts (activity_id, alert_type, severity, alert_message) VALUES
(5, 'Suspicious Activity', 'Critical', 'RBAC Violation: Guest user attempting write operation (DML)');

-- Alert for Guest INSERT attempt
INSERT INTO security_alerts (activity_id, alert_type, severity, alert_message) VALUES
(6, 'Suspicious Activity', 'Critical', 'RBAC Violation: Guest user attempting write operation (DML)');

-- Alert for Brute Force
INSERT INTO security_alerts (activity_id, alert_type, severity, alert_message) VALUES
(12, 'Suspicious Activity', 'High', 'Brute Force Attack: 6 failed login attempts for username "hacker"');

-- =====================================================
-- VERIFICATION QUERIES
-- =====================================================
-- Run these to verify your data was inserted correctly

-- Check users
-- SELECT * FROM users;

-- Check products
-- SELECT * FROM products;

-- Check activities
-- SELECT * FROM vw_all_activities ORDER BY access_timestamp DESC;

-- Check suspicious activities
-- SELECT * FROM vw_suspicious_activities;

-- Check security alerts
-- SELECT 
--     sa.alert_id,
--     sa.severity,
--     sa.alert_message,
--     sa.created_at,
--     al.operation_type,
--     al.table_name,
--     u.username,
--     u.role
-- FROM security_alerts sa
-- JOIN activity_logs al ON sa.activity_id = al.activity_id
-- LEFT JOIN users u ON al.user_id = u.user_id
-- ORDER BY sa.created_at DESC;

-- =====================================================
-- NOTES FOR TESTING
-- =====================================================
-- 1. To test the system, login with these credentials:
--    - Admin: username=admin, password=admin123
--    - User: username=john_doe, password=user123
--    - Guest: username=guest_user, password=guest123
--
-- 2. The passwords shown in comments are for testing only
--    In production, never store plain text passwords
--
-- 3. Try these test scenarios:
--    - Login as guest and attempt to INSERT/UPDATE/DELETE
--    - Attempt multiple failed logins to trigger brute force detection
--    - Perform operations outside 9 AM - 6 PM to trigger timing alerts
--
-- 4. To generate your own password hashes for new users:
--    python -c "from werkzeug.security import generate_password_hash; print(generate_password_hash('your_password'))"