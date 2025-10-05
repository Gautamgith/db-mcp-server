-- Setup script for PostgreSQL IAM database user
-- Run this script as the master user to create IAM authentication user

-- Create IAM user for MCP server
CREATE USER mcp_server;

-- Grant IAM authentication
GRANT rds_iam TO mcp_server;

-- Grant necessary permissions for read-only access
GRANT CONNECT ON DATABASE mcpserver TO mcp_server;
GRANT USAGE ON SCHEMA public TO mcp_server;
GRANT USAGE ON SCHEMA information_schema TO mcp_server;

-- Grant SELECT permissions on all existing tables
GRANT SELECT ON ALL TABLES IN SCHEMA public TO mcp_server;
GRANT SELECT ON ALL SEQUENCES IN SCHEMA public TO mcp_server;

-- Grant SELECT permissions on system catalogs for introspection
GRANT SELECT ON ALL TABLES IN SCHEMA information_schema TO mcp_server;
GRANT SELECT ON pg_catalog.pg_indexes TO mcp_server;
GRANT SELECT ON pg_catalog.pg_class TO mcp_server;
GRANT SELECT ON pg_catalog.pg_namespace TO mcp_server;
GRANT SELECT ON pg_catalog.pg_attribute TO mcp_server;
GRANT SELECT ON pg_catalog.pg_constraint TO mcp_server;
GRANT SELECT ON pg_catalog.pg_index TO mcp_server;

-- Grant permissions on future tables (for new tables created later)
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO mcp_server;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON SEQUENCES TO mcp_server;

-- Verify user creation
SELECT
    usename as username,
    usesuper as is_superuser,
    usecreatedb as can_create_db,
    usebypassrls as can_bypass_rls
FROM pg_user
WHERE usename = 'mcp_server';

-- Show granted permissions
SELECT
    schemaname,
    tablename,
    has_table_privilege('mcp_server', schemaname||'.'||tablename, 'SELECT') as has_select
FROM pg_tables
WHERE schemaname IN ('public', 'information_schema')
LIMIT 10;