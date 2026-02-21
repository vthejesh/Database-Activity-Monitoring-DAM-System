-- 03_create_admin_user.sql
-- Create default admin user

USE dam_system;

-- Insert default admin user if not exists
-- Password: admin123 (hashed with bcrypt)
INSERT IGNORE INTO users (username, password_hash, role, account_status, created_at)
VALUES (
    'admin', 
    'pbkdf2:sha256:600000$DoFHEl6gFfJYQnM6$8c9c5d4b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a0f9e8d7c6b5a4f3e2d1c',
    'Admin', 
    'Active', 
    NOW()
);

-- Insert a test user (password: user123)
INSERT IGNORE INTO users (username, password_hash, role, account_status, created_at)
VALUES (
    'user1', 
    'pbkdf2:sha256:600000$DoFHEl6gFfJYQnM6$8c9c5d4b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a0f9e8d7c6b5a4f3e2d1c',
    'User', 
    'Active', 
    NOW()
);

-- Insert a guest user (password: guest123)
INSERT IGNORE INTO users (username, password_hash, role, account_status, created_at)
VALUES (
    'guest1', 
    'pbkdf2:sha256:600000$DoFHEl6gFfJYQnM6$8c9c5d4b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a0f9e8d7c6b5a4f3e2d1c',
    'Guest', 
    'Active', 
    NOW()
);

-- Show created users
SELECT user_id, username, role, account_status FROM users;
SELECT 'Default users created successfully' AS 'Status';