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


INSERT INTO users (username, password_hash, role, account_status) VALUES
('admin', 'scrypt:32768:8:1$cJxzSVQj2xhfzJvz$01809c44f546d83060edc74959b3398a7264baab8be1f16a0cf5ee3d41f8ec47c5a42c407a99b8f1ca72d752183845a998fb5fed80c33e8f334d9a621f42e799', 'Admin', 'Active');

INSERT INTO users (username, password_hash, role, account_status) VALUES
('john_doe', 'scrypt:32768:8:1$q5uws5zEDIzoXD6M$380de2d44e6cca3755d1f9af4edb28f9833f3b526d9720c29133c2408215414017d787d5e0f66e2988f3a8affe67c1a249a6e78aa1dc1fabbda6d82c0525e336', 'User', 'Active');

INSERT INTO users (username, password_hash, role, account_status) VALUES
('jane_smith', 'scrypt:32768:8:1$oK9f6OAndKvaSuVT$13ff43a64b2661d0effcfa5dd4f27104a278565b9081f002df21ae35f60c899c4d0d23b162d2bbf0510a270e8a648094f8faef13acb15ea0341e94cd720d1f44', 'User', 'Active');

INSERT INTO users (username, password_hash, role, account_status) VALUES
('guest_user', 'scrypt:32768:8:1$HoJV8zsfhVg1TR2P$b98e5dbeed6301bf0e86a2477bb47ee929f21f28fe3499582a6034e1db1000a505e305cf2d274e6fbd6db935260038cfd3eb540303917e80cfb99ebdf91a1c8a', 'Guest', 'Active');

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
(NULL, 'LOGIN', 'users', 'Failed', 'Attempted username: hacker. Invalid credentials', '192.168.1.200'),
(NULL, 'LOGIN', 'users', 'Failed', 'Attempted username: hacker. Invalid credentials', '192.168.1.200'),
(NULL, 'LOGIN', 'users', 'Failed', 'Attempted username: hacker. Invalid credentials', '192.168.1.200'),
(NULL, 'LOGIN', 'users', 'Failed', 'Attempted username: hacker. Invalid credentials', '192.168.1.200'),
(NULL, 'LOGIN', 'users', 'Failed', 'Attempted username: hacker. Invalid credentials', '192.168.1.200'),
(NULL, 'LOGIN', 'users', 'Failed', 'Attempted username: hacker. Invalid credentials', '192.168.1.200');

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
INSERT INTO security_alerts (activity_id, alert_type, severity, alert_message)
SELECT activity_id, 'Suspicious Activity', 'High',
       'Brute Force Attack: 6 failed login attempts for username "hacker"'
FROM activity_logs
WHERE is_suspicious = TRUE
ORDER BY activity_id DESC
LIMIT 1;


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