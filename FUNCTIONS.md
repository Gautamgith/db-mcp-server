# MCP Tools Reference

Complete reference for all 10 MCP tools provided by the PostgreSQL MCP Server.

## Overview

All tools include:
- **Security validation** - SQL injection prevention, complexity analysis
- **Rate limiting** - Configurable request throttling
- **Audit logging** - Complete execution trail
- **Error handling** - Consistent error responses with detailed context

**Authentication modes:** All tools work with both standard and IAM authentication (configured via `USE_IAM_AUTH` environment variable).

---

## Database Introspection Tools

### `list_tables`

List all tables in a PostgreSQL schema.

**Parameters:**
- `schema_name` (string, optional): Schema name (defaults to 'public')

**Returns:**
```json
{
  "tables": [
    {
      "table_name": "users",
      "schema_name": "public",
      "table_type": "BASE TABLE"
    },
    {
      "table_name": "orders",
      "schema_name": "public",
      "table_type": "BASE TABLE"
    }
  ],
  "schema_name": "public",
  "count": 2,
  "authentication_method": "IAM"
}
```

**Example Request:**
```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "list_tables",
    "arguments": {
      "schema_name": "public"
    }
  },
  "id": 1
}
```

---

### `describe_table`

Get detailed schema information for a specific table including columns, data types, indexes, and foreign keys.

**Parameters:**
- `table_name` (string, **required**): Name of the table to describe
- `schema_name` (string, optional): Schema name (defaults to 'public')

**Returns:**
```json
{
  "table_info": {
    "table_name": "users",
    "schema_name": "public",
    "columns": [
      {
        "column_name": "id",
        "data_type": "integer",
        "is_nullable": false,
        "column_default": "nextval('users_id_seq'::regclass)",
        "is_primary_key": true
      },
      {
        "column_name": "email",
        "data_type": "character varying",
        "is_nullable": false,
        "column_default": null,
        "is_primary_key": false
      },
      {
        "column_name": "created_at",
        "data_type": "timestamp without time zone",
        "is_nullable": false,
        "column_default": "CURRENT_TIMESTAMP",
        "is_primary_key": false
      }
    ],
    "indexes": [
      {
        "index_name": "users_pkey",
        "column_names": ["id"],
        "is_unique": true,
        "is_primary": true
      },
      {
        "index_name": "users_email_idx",
        "column_names": ["email"],
        "is_unique": true,
        "is_primary": false
      }
    ],
    "foreign_keys": []
  },
  "authentication_method": "IAM"
}
```

**Example Request:**
```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "describe_table",
    "arguments": {
      "table_name": "users",
      "schema_name": "public"
    }
  },
  "id": 2
}
```

---

## Query Execution Tools

### `execute_query`

Execute a parameterized SELECT query with comprehensive security validation including SQL injection prevention, complexity analysis, and rate limiting.

**Parameters:**
- `query` (string, **required**): SQL SELECT statement with parameter placeholders ($1, $2, etc.)
- `parameters` (array, optional): Parameter values for query placeholders (default: [])
- `limit` (number, optional): Maximum number of rows to return (default: 100, max: 1000)

**Security Features:**
- Only SELECT queries allowed
- Parameterized query enforcement
- SQL injection pattern detection
- Query complexity scoring
- Size validation (max 10,000 characters by default)
- Result row limiting

**Returns:**
```json
{
  "rows": [
    {"id": 1, "name": "John Doe", "email": "john@example.com"},
    {"id": 2, "name": "Jane Smith", "email": "jane@example.com"}
  ],
  "row_count": 2,
  "execution_time_ms": 15,
  "security_validated": true,
  "complexity_score": 3,
  "authentication_method": "IAM"
}
```

**Example Requests:**

Simple query:
```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "execute_query",
    "arguments": {
      "query": "SELECT * FROM users LIMIT 10"
    }
  },
  "id": 3
}
```

Parameterized query:
```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "execute_query",
    "arguments": {
      "query": "SELECT id, name, email FROM users WHERE status = $1 AND created_at > $2",
      "parameters": ["active", "2024-01-01"],
      "limit": 50
    }
  },
  "id": 4
}
```

**Error Example:**
```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": -32002,
    "message": "Query security validation failed: Potential SQL injection detected, Dangerous keyword found: DROP",
    "data": {
      "error_type": "SQL_INJECTION_RISK",
      "details": "Query security validation failed: Potential SQL injection detected",
      "query_id": "q_1234567890_abc123"
    }
  },
  "id": 4
}
```

---

### `structured_query`

Execute a query using predefined secure patterns for common database operations. Patterns are pre-validated and optimized for safety.

**Parameters:**
- `pattern_name` (string, **required**): Name of the query pattern to use
- `parameters` (object, **required**): Parameters for the query pattern
- `limit` (number, optional): Maximum number of rows to return (default: 100, max: 1000)

**Available Patterns:**
Use `query_patterns` tool to see all available patterns and their parameters.

**Returns:**
```json
{
  "rows": [
    {"id": 1, "name": "John Doe"}
  ],
  "row_count": 1,
  "execution_time_ms": 12,
  "query_pattern": "select_by_id",
  "security_validated": true,
  "authentication_method": "IAM"
}
```

**Example Request:**
```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "structured_query",
    "arguments": {
      "pattern_name": "select_by_id",
      "parameters": {
        "table_name": "users",
        "id": 123
      },
      "limit": 10
    }
  },
  "id": 5
}
```

---

## Security & Analysis Tools

### `query_patterns`

List all available secure query patterns with their descriptions, parameters, and configuration.

**Parameters:** None

**Returns:**
```json
{
  "patterns": [
    {
      "name": "select_all",
      "description": "Select all columns from a table",
      "parameters": {
        "table_name": "string (required)"
      },
      "max_rows": 100,
      "requires_explicit_limit": true
    },
    {
      "name": "select_by_id",
      "description": "Select a single row by primary key ID",
      "parameters": {
        "table_name": "string (required)",
        "id": "number (required)"
      },
      "max_rows": 1,
      "requires_explicit_limit": false
    },
    {
      "name": "select_columns",
      "description": "Select specific columns from a table",
      "parameters": {
        "table_name": "string (required)",
        "columns": "array of strings (required)"
      },
      "max_rows": 100,
      "requires_explicit_limit": true
    }
  ],
  "total_patterns": 15,
  "security_features": [
    "Input validation",
    "SQL injection protection",
    "Parameter sanitization",
    "Query complexity analysis",
    "Rate limiting"
  ]
}
```

**Example Request:**
```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "query_patterns"
  },
  "id": 6
}
```

---

### `analyze_query_complexity`

Analyze the complexity of a SQL query without executing it. Provides complexity scoring, security validation, and optimization recommendations.

**Parameters:**
- `query` (string, **required**): SQL query to analyze

**Returns:**
```json
{
  "size_analysis": {
    "allowed": true,
    "size": 245,
    "max_size": 10000
  },
  "complexity_analysis": {
    "score": 12,
    "maxScore": 20,
    "allowed": true,
    "factors": [
      "3 JOIN(s)",
      "2 subquery(ies)",
      "1 DISTINCT clause"
    ]
  },
  "security_validation": {
    "is_valid": true,
    "errors": []
  },
  "recommendations": [
    "Query appears to follow security best practices"
  ]
}
```

**Complexity Factors:**
- Each JOIN: +3 points
- Each subquery: +2 points
- Each UNION: +2 points
- DISTINCT clause: +1 point
- Window functions: +3 points
- CTEs (WITH): +2 points each

**Example Request:**
```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "analyze_query_complexity",
    "arguments": {
      "query": "SELECT u.name, COUNT(o.id) as order_count FROM users u LEFT JOIN orders o ON u.id = o.user_id GROUP BY u.name"
    }
  },
  "id": 7
}
```

---

### `validate_query_syntax`

Validate SQL query syntax without executing it. Uses PostgreSQL's EXPLAIN functionality to check for syntax errors.

**Parameters:**
- `query` (string, **required**): SQL query to validate

**Returns:**
```json
{
  "is_valid": true,
  "query_length": 156,
  "message": "Query syntax is valid"
}
```

**Error Example:**
```json
{
  "is_valid": false,
  "query_length": 45,
  "error": "syntax error at or near \"FORM\""
}
```

**Example Request:**
```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "validate_query_syntax",
    "arguments": {
      "query": "SELECT * FROM users WHERE id = 1"
    }
  },
  "id": 8
}
```

---

## System Monitoring Tools

### `connection_health`

Check database connection health and authentication status. For IAM mode, includes token expiration information.

**Parameters:** None

**Returns (Standard Mode):**
```json
{
  "authentication_method": "Standard",
  "status": "healthy"
}
```

**Returns (IAM Mode):**
```json
{
  "authentication_method": "IAM",
  "status": "healthy",
  "is_connected": true,
  "token_expires_in_ms": 720000,
  "reconnect_attempts": 0,
  "last_activity": "2024-10-24T08:30:15.123Z"
}
```

**Example Request:**
```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "connection_health"
  },
  "id": 9
}
```

---

### `security_status`

Get comprehensive security system status including rate limiting configuration, query patterns, and complexity limits.

**Parameters:** None

**Returns:**
```json
{
  "rate_limiting": {
    "active_windows": 3,
    "max_requests_per_window": 100,
    "window_duration_ms": 60000
  },
  "query_patterns": {
    "available_patterns": 15,
    "pattern_names": [
      "select_all",
      "select_by_id",
      "select_columns",
      "select_where",
      "...etc"
    ]
  },
  "complexity_limits": {
    "max_query_size": 10000,
    "max_complexity_score": 20
  },
  "authentication_method": "IAM",
  "security_features_enabled": [
    "SQL injection prevention",
    "Query pattern validation",
    "Complexity analysis",
    "Rate limiting",
    "Parameter sanitization",
    "Input validation"
  ]
}
```

**Example Request:**
```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "security_status"
  },
  "id": 10
}
```

---

### `rate_limit_status`

Check current rate limiting status and configuration.

**Parameters:** None

**Returns:**
```json
{
  "total_active_windows": 3,
  "max_requests_per_window": 100,
  "window_duration_ms": 60000,
  "message": "Rate limiting is active and monitoring requests"
}
```

**Example Request:**
```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "rate_limit_status"
  },
  "id": 11
}
```

---

## Error Handling

### Error Response Format

All errors follow MCP standard format:

```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": -32000,
    "message": "Human-readable error message",
    "data": {
      "error_type": "ERROR_CATEGORY",
      "details": "Detailed error information",
      "query_id": "unique-query-identifier"
    }
  },
  "id": 1
}
```

### Error Codes

| Code | Category | Description |
|------|----------|-------------|
| -32000 | DATABASE_ERROR | Database connection or execution errors |
| -32002 | VALIDATION_ERROR | Query validation, SQL injection, or complexity errors |
| -32003 | PARAMETER_ERROR | Invalid or missing parameters |
| -32429 | RATE_LIMIT_EXCEEDED | Rate limit threshold reached |

### Error Types

- **`DATABASE_ERROR`** - Connection timeouts, query execution failures
- **`SQL_INJECTION_RISK`** - Potential SQL injection detected
- **`QUERY_TOO_LARGE`** - Query exceeds max size limit
- **`QUERY_TOO_COMPLEX`** - Query complexity score too high
- **`VALIDATION_ERROR`** - Invalid pattern name or parameters
- **`PARAMETER_ERROR`** - Missing or invalid parameter types
- **`RATE_LIMIT_EXCEEDED`** - Too many requests in time window
- **`EXECUTION_ERROR`** - Query execution failed

### Rate Limit Error Example

```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": -32429,
    "message": "Rate limit exceeded. Try again in 45 seconds.",
    "data": {
      "error_type": "RATE_LIMIT_EXCEEDED",
      "details": "Rate limit exceeded. Try again in 45 seconds.",
      "retry_after": "45"
    }
  },
  "id": 12
}
```

---

## Security Considerations

### Query Validation Rules

1. **Only SELECT queries allowed** - No INSERT, UPDATE, DELETE, DROP, etc.
2. **Parameterized queries enforced** - Direct value substitution not allowed
3. **Dangerous keywords blocked** - DROP, DELETE, TRUNCATE, ALTER, etc.
4. **Comment stripping** - SQL comments removed to prevent injection
5. **Size limits enforced** - Maximum 10,000 characters (configurable)
6. **Complexity scoring** - Automatic rejection of overly complex queries

### Rate Limiting

- Default: 100 requests per 60-second window
- Per-client tracking (when client ID available)
- Automatic window cleanup
- Configurable via environment variables

### Best Practices

1. **Always use parameterized queries** - Never concatenate user input
2. **Use structured queries** when possible - Pre-validated patterns
3. **Set appropriate limits** - Don't request more data than needed
4. **Monitor complexity scores** - Optimize high-complexity queries
5. **Check connection health** - Ensure IAM tokens are valid
6. **Review audit logs** - Monitor for suspicious patterns

---

## Performance Considerations

### Connection Management
- Connection pooling (2-10 connections, configurable)
- Automatic IAM token refresh (every 13 minutes)
- Connection health checks
- Graceful error recovery

### Query Optimization
- Default row limits (100, max 1000)
- Query timeout enforcement (30 seconds default)
- Schema information caching
- Efficient result streaming

### Recommended Limits

| Setting | Default | Recommended Range | Purpose |
|---------|---------|-------------------|---------|
| Row Limit | 100 | 10-500 | Balance speed vs data completeness |
| Complexity Score | 20 | 15-25 | Prevent expensive queries |
| Query Size | 10000 | 5000-20000 | Reasonable query length |
| Rate Limit | 100/min | 50-200/min | Prevent abuse |

---

## Usage Examples

### Basic Workflow

```bash
# 1. List available tables
curl -X POST http://localhost:3000/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"list_tables"},"id":1}'

# 2. Describe a specific table
curl -X POST http://localhost:3000/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"describe_table","arguments":{"table_name":"users"}},"id":2}'

# 3. Query the table
curl -X POST http://localhost:3000/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"execute_query","arguments":{"query":"SELECT * FROM users LIMIT 5"}},"id":3}'
```

### Security Analysis Workflow

```bash
# 1. Check security status
curl -X POST http://localhost:3000/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"security_status"},"id":1}'

# 2. Analyze query complexity before execution
curl -X POST http://localhost:3000/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"analyze_query_complexity","arguments":{"query":"SELECT * FROM users"}},"id":2}'

# 3. Execute if complexity is acceptable
curl -X POST http://localhost:3000/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"execute_query","arguments":{"query":"SELECT * FROM users","limit":10}},"id":3}'
```

---

## Tool Comparison Matrix

| Tool | Purpose | Executes Query | Security Validation | Use Case |
|------|---------|----------------|---------------------|----------|
| `list_tables` | Introspection | Yes (metadata) | N/A | Discover database structure |
| `describe_table` | Introspection | Yes (metadata) | N/A | Understand table schema |
| `execute_query` | Query | Yes | Full | Flexible querying with full security |
| `structured_query` | Query | Yes | Pre-validated | Safe common operations |
| `query_patterns` | Info | No | N/A | Discover available patterns |
| `analyze_query_complexity` | Analysis | No | Yes | Pre-flight query validation |
| `validate_query_syntax` | Analysis | No (EXPLAIN only) | Yes | Syntax checking |
| `connection_health` | Monitoring | Yes (health check) | N/A | Verify connectivity |
| `security_status` | Monitoring | No | N/A | Check security configuration |
| `rate_limit_status` | Monitoring | No | N/A | Monitor request throttling |

---

## Additional Resources

- **[README.md](./README.md)** - Quick start and overview
- **[SECURITY_ARCHITECTURE.md](./SECURITY_ARCHITECTURE.md)** - Detailed security framework
- **[TESTING_GUIDE.md](./TESTING_GUIDE.md)** - MCP Inspector testing procedures
- **[DEPLOYMENT.md](./DEPLOYMENT.md)** - Production deployment guide
