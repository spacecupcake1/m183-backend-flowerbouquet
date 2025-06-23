-- Create restricted application user
CREATE USER flowerbouquet_app WITH PASSWORD 'FlowerApp2024!@#SecurePass';

-- Create database
CREATE DATABASE flowerbouquet_prod OWNER flowerbouquet_app;

-- Connect to the new database
\c flowerbouquet_prod;

-- Grant only necessary permissions
GRANT CONNECT ON DATABASE flowerbouquet_prod TO flowerbouquet_app;
GRANT USAGE ON SCHEMA public TO flowerbouquet_app;
GRANT CREATE ON SCHEMA public TO flowerbouquet_app;

-- Table-specific permissions (run after Flyway migration)
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO flowerbouquet_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO flowerbouquet_app;

-- Future tables
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO flowerbouquet_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO flowerbouquet_app;

-- Create read-only user for reporting
CREATE USER flowerbouquet_readonly WITH PASSWORD 'FlowerRead2024!@#';
GRANT CONNECT ON DATABASE flowerbouquet_prod TO flowerbouquet_readonly;
GRANT USAGE ON SCHEMA public TO flowerbouquet_readonly;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO flowerbouquet_readonly;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO flowerbouquet_readonly;

-- Security policies
ALTER SYSTEM SET log_statement = 'mod';
ALTER SYSTEM SET log_min_duration_statement = 1000;
ALTER SYSTEM SET log_connections = on;
ALTER SYSTEM SET log_disconnections = on;

-- Reload configuration
SELECT pg_reload_conf();
