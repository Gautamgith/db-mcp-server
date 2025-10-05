# MCP Server Testing Guide with McpInspector

## Overview

This guide provides comprehensive testing procedures for the PostgreSQL MCP Server using McpInspector, covering all 17 available tools across three security tiers.

## Prerequisites

1. **McpInspector Installation**
   ```bash
   npm install -g @modelcontextprotocol/inspector
   ```

2. **MCP Server Build**
   ```bash
   npm run build
   ```

3. **Database Setup** (for local testing)
   ```bash
   # Using Docker for local PostgreSQL
   docker run --name postgres-test -e POSTGRES_PASSWORD=testpass -e POSTGRES_DB=testdb -p 5432:5432 -d postgres:13

   # Create test data
   docker exec -it postgres-test psql -U postgres -d testdb -c "
   CREATE TABLE users (id SERIAL PRIMARY KEY, name VARCHAR(100), email VARCHAR(100), created_at TIMESTAMP DEFAULT NOW());
   INSERT INTO users (name, email) VALUES ('John Doe', 'john@example.com'), ('Jane Smith', 'jane@example.com');
   "
   ```

## Testing Configuration

### Basic MCP Server Testing
```bash
# Start McpInspector with basic server
mcp-inspector --server-command "npm run dev" --server-args ""
```

### IAM-Enabled Testing
```bash
# Set environment variables for IAM testing
export AWS_REGION=us-east-1
export AWS_PROFILE=your-profile
export DATABASE_URL=postgresql://your-iam-user@your-rds-endpoint:5432/your-database

# Start with IAM server
mcp-inspector --server-command "npm run dev:iam" --server-args ""
```

### Secure Server Testing
```bash
# Start with secure server (includes all features)
mcp-inspector --server-command "npm run dev:secure" --server-args ""
```

## Tool Testing Matrix

### Tier 1: Basic Tools (3 tools)

#### 1. list_tables
**Purpose**: List all tables in the database
**Test Cases**:
```json
{
  "name": "list_tables",
  "arguments": {}
}
```
**Expected Result**: Array of table objects with names and row counts

#### 2. describe_table
**Purpose**: Get detailed table schema information
**Test Cases**:
```json
{
  "name": "describe_table",
  "arguments": {
    "table_name": "users"
  }
}
```
**Expected Result**: Column definitions, data types, constraints

#### 3. execute_select
**Purpose**: Execute parameterized SELECT queries
**Test Cases**:
```json
{
  "name": "execute_select",
  "arguments": {
    "query": "SELECT * FROM users LIMIT $1",
    "parameters": [5]
  }
}
```
**Expected Result**: Query results with specified row limit

### Tier 2: IAM-Authenticated Tools (4 tools)

#### 4. list_tables_iam
**Purpose**: IAM-authenticated table listing
**Prerequisites**: Valid AWS credentials and IAM database user
**Test Cases**:
```json
{
  "name": "list_tables_iam",
  "arguments": {}
}
```

#### 5. describe_table_iam
**Purpose**: IAM-authenticated table description
**Test Cases**:
```json
{
  "name": "describe_table_iam",
  "arguments": {
    "table_name": "users"
  }
}
```

#### 6. execute_select_iam
**Purpose**: IAM-authenticated query execution
**Test Cases**:
```json
{
  "name": "execute_select_iam",
  "arguments": {
    "query": "SELECT COUNT(*) FROM users",
    "parameters": []
  }
}
```

#### 7. connection_health_iam
**Purpose**: Verify IAM database connectivity
**Test Cases**:
```json
{
  "name": "connection_health_iam",
  "arguments": {}
}
```

### Tier 3: Secure Tools (10 tools)

#### 8. structured_query_secure
**Purpose**: Execute predefined secure query patterns
**Test Cases**:
```json
{
  "name": "structured_query_secure",
  "arguments": {
    "pattern": "table_exploration",
    "parameters": {
      "table": "users",
      "limit": 10
    }
  }
}
```

#### 9. validated_query_secure
**Purpose**: Execute custom queries with advanced validation
**Test Cases**:
```json
{
  "name": "validated_query_secure",
  "arguments": {
    "query": "SELECT name, email FROM users WHERE id > $1",
    "parameters": [1],
    "limit": 50
  }
}
```

#### 10. query_patterns_secure
**Purpose**: List all available secure query patterns
**Test Cases**:
```json
{
  "name": "query_patterns_secure",
  "arguments": {}
}
```

#### 11. analyze_query_complexity
**Purpose**: Analyze query complexity and performance
**Test Cases**:
```json
{
  "name": "analyze_query_complexity",
  "arguments": {
    "query": "SELECT u.name, COUNT(o.id) FROM users u LEFT JOIN orders o ON u.id = o.user_id GROUP BY u.id, u.name"
  }
}
```

#### 12. security_status
**Purpose**: Check security system status and configuration
**Test Cases**:
```json
{
  "name": "security_status",
  "arguments": {}
}
```

#### 13. audit_query_history
**Purpose**: Retrieve query execution audit trail
**Test Cases**:
```json
{
  "name": "audit_query_history",
  "arguments": {
    "limit": 10
  }
}
```

#### 14. performance_metrics
**Purpose**: Get database performance statistics
**Test Cases**:
```json
{
  "name": "performance_metrics",
  "arguments": {}
}
```

#### 15. rate_limit_status
**Purpose**: Check current rate limiting status
**Test Cases**:
```json
{
  "name": "rate_limit_status",
  "arguments": {}
}
```

#### 16. validate_query_syntax
**Purpose**: Validate SQL query syntax without execution
**Test Cases**:
```json
{
  "name": "validate_query_syntax",
  "arguments": {
    "query": "SELECT * FROM users WHERE name = $1"
  }
}
```

#### 17. schema_relationships
**Purpose**: Analyze table relationships and foreign keys
**Test Cases**:
```json
{
  "name": "schema_relationships",
  "arguments": {
    "table_name": "users"
  }
}
```

## Security Testing Scenarios

### SQL Injection Prevention Tests
Test these malicious queries should be rejected:
```json
{
  "name": "validated_query_secure",
  "arguments": {
    "query": "SELECT * FROM users; DROP TABLE users; --",
    "parameters": []
  }
}
```

### Rate Limiting Tests
Execute multiple rapid requests to test throttling:
```bash
# Use a script to test rate limiting
for i in {1..20}; do
  echo "Request $i"
  # Execute the same tool call rapidly
done
```

### Authentication Tests
Test IAM token refresh and expiration handling:
```json
{
  "name": "connection_health_iam",
  "arguments": {}
}
```

## Expected Test Results

### Success Criteria
1. **All Basic Tools**: Should work with local PostgreSQL connection
2. **IAM Tools**: Should authenticate and execute with valid AWS credentials
3. **Secure Tools**: Should provide enhanced validation and security features
4. **Security Validation**: Malicious queries should be rejected
5. **Rate Limiting**: Should enforce request throttling
6. **Audit Logging**: Should track all query executions

### Performance Benchmarks
- **Query Response Time**: < 5 seconds for standard operations
- **Connection Establishment**: < 2 seconds
- **Rate Limit Response**: Immediate rejection when exceeded
- **Security Validation**: < 1 second for query analysis

## Testing Checklist

### Basic Functionality ✓
- [ ] Server starts successfully
- [ ] McpInspector connects to server
- [ ] All 17 tools are visible in inspector
- [ ] Basic database operations work

### Security Features ✓
- [ ] SQL injection attempts are blocked
- [ ] Rate limiting enforces limits
- [ ] Audit logs are generated
- [ ] Query complexity analysis works

### IAM Authentication ✓
- [ ] IAM token generation succeeds
- [ ] Database connection with IAM works
- [ ] Token refresh handles expiration
- [ ] Authentication failures are logged

### Error Handling ✓
- [ ] Invalid queries return proper errors
- [ ] Network issues are handled gracefully
- [ ] Authentication failures are reported
- [ ] Rate limit exceeded returns appropriate response

## Troubleshooting

### Common Issues

#### McpInspector Connection Failed
```bash
# Check server logs
npm run dev:secure 2>&1 | tee server.log

# Verify server responds to stdio
echo '{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}' | npm run dev:secure
```

#### IAM Authentication Issues
```bash
# Verify AWS credentials
aws sts get-caller-identity

# Check RDS IAM user exists
aws rds describe-db-instances --db-instance-identifier your-instance
```

#### Database Connection Problems
```bash
# Test direct connection
psql -h localhost -U postgres -d testdb

# Check network connectivity
telnet your-rds-endpoint 5432
```

## Integration Testing

### With GitHub Copilot
1. Configure MCP server in VSCode
2. Test natural language queries
3. Verify security controls apply

### With Custom LLM
1. Use MCP client library
2. Test programmatic tool calls
3. Verify audit logging captures context

### Performance Testing
1. Load test with multiple concurrent requests
2. Monitor memory and CPU usage
3. Test with large result sets

## Continuous Testing

### Automated Test Suite
```bash
# Run comprehensive test suite
npm run test:mcp-inspector
```

### CI/CD Integration
- Tests run automatically on code changes
- Security scanning validates configurations
- Performance benchmarks track regression

## Documentation Links

- [Model Context Protocol Specification](https://spec.modelcontextprotocol.io/)
- [McpInspector Documentation](https://github.com/modelcontextprotocol/inspector)
- [PostgreSQL MCP Server API Reference](./API_REFERENCE.md)
- [Security Architecture](./SECURITY_ARCHITECTURE.md)