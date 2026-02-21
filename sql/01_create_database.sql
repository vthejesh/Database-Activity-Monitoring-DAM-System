-- 01_create_database.sql
-- Create the DAM system database

CREATE DATABASE IF NOT EXISTS dam_system;
USE dam_system;

SELECT 'Database dam_system created or already exists' AS 'Status';