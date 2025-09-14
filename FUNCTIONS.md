# Function Documentation

## MCP Tools Reference

This document provides detailed information about all available MCP tools and their usage.

## Phase 1: Basic Query Tools

### `list_tables`
Lists all tables in the connected PostgreSQL database.

**Parameters:** None

**Returns:**
```json
{
  "tables": [
    {
      "table_name": "users",
      "schema_name": "public",
      "table_type": "BASE TABLE"
    }
  ]
}
```

**Example:**
```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "list_tables"
  },
  "id": 1
}
```

### `describe_table`
Get detailed schema information for a specific table.

**Parameters:**
- `table_name` (string, required): Name of the table
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
      }
    ],
    "indexes": [],
    "foreign_keys": []
  }
}
```

**Example:**
```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "describe_table",
    "arguments": {
      "table_name": "users"
    }
  },
  "id": 2
}
```

### `execute_select`
Execute a parameterized SELECT query.

**Parameters:**
- `query` (string, required): SQL SELECT statement with parameter placeholders
- `parameters` (array, optional): Parameter values for placeholders
- `limit` (number, optional): Maximum number of rows to return (default: 100)

**Security Notes:**
- Only SELECT statements are allowed
- All parameters are properly escaped
- Query must match allowed patterns

**Returns:**
```json
{
  "rows": [
    {"id": 1, "name": "John Doe", "email": "john@example.com"}
  ],
  "row_count": 1,
  "execution_time_ms": 15
}
```

**Example:**
```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "execute_select",
    "arguments": {
      "query": "SELECT * FROM users WHERE id = $1",
      "parameters": [1],
      "limit": 10
    }
  },
  "id": 3
}
```

## Phase 2: IAM Authentication (Future)

### Internal Functions

#### `generateIAMToken()`
Generates IAM authentication token for RDS access.

**Implementation Details:**
- Uses AWS SDK v3 RDS Signer
- Tokens valid for 15 minutes
- Automatic rotation before expiry
- Uses EC2 instance role credentials

#### `refreshConnection()`
Refreshes database connection with new IAM token.

**Trigger Conditions:**
- Token approaching expiry (< 2 minutes remaining)
- Connection failure due to authentication
- Manual refresh request

## Phase 3: Advanced Security Tools (Future)

### `join_tables`
Execute controlled table joins with validation.

**Parameters:**
- `primary_table` (string): Main table for the join
- `join_table` (string): Table to join with
- `join_condition` (string): Join condition (validated)
- `select_columns` (array): Specific columns to select
- `where_clause` (object): Structured WHERE conditions

### `aggregate_query`
Execute safe aggregation queries.

**Parameters:**
- `table_name` (string): Target table
- `group_by` (array): Columns to group by
- `aggregations` (array): Aggregation functions to apply
- `having_clause` (object): HAVING conditions
- `order_by` (array): Ordering specifications

### `filtered_search`
Advanced search with multiple filter conditions.

**Parameters:**
- `table_name` (string): Target table
- `filters` (object): Structured filter conditions
- `search_columns` (array): Columns to search in
- `sort_options` (object): Sorting configuration
- `pagination` (object): Pagination settings

## Phase 4: Logging Functions (Future)

### Internal Logging Functions

#### `logQuery(queryInfo)`
Logs query execution details.

**Logged Information:**
- Query text (sanitized)
- Parameters (hashed for security)
- Execution time
- Result row count
- User context
- Timestamp

#### `logError(error, context)`
Logs error information with context.

**Error Categories:**
- Database connection errors
- Query execution errors
- Authentication failures
- Input validation errors

#### `logPerformance(metrics)`
Logs performance metrics.

**Metrics Tracked:**
- Query execution time
- Connection pool usage
- Memory usage
- Token refresh frequency

## Error Handling

### Error Response Format
All errors follow a consistent format:

```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": -32000,
    "message": "Database connection failed",
    "data": {
      "error_type": "CONNECTION_ERROR",
      "details": "Connection timeout after 5 seconds",
      "query_id": "uuid-here"
    }
  },
  "id": 1
}
```

### Error Codes
- `-32000`: Database errors
- `-32001`: Authentication errors
- `-32002`: Query validation errors
- `-32003`: Parameter errors
- `-32004`: Permission errors

### Error Types
- `CONNECTION_ERROR`: Database connection issues
- `AUTH_ERROR`: IAM authentication failures
- `VALIDATION_ERROR`: Input validation failures
- `EXECUTION_ERROR`: Query execution problems
- `TIMEOUT_ERROR`: Operation timeouts

## Security Considerations

### Query Validation
1. **SQL Injection Prevention**: All queries use parameterized statements
2. **Query Allowlisting**: Only approved query patterns allowed
3. **Input Sanitization**: All inputs validated before processing
4. **Result Limiting**: Maximum row limits enforced

### Authentication Flow
1. **Token Generation**: IAM tokens generated on-demand
2. **Token Validation**: Tokens validated before each connection
3. **Automatic Rotation**: Tokens refreshed before expiry
4. **Error Handling**: Graceful handling of auth failures

### Logging Security
1. **Parameter Sanitization**: Sensitive data hashed or removed
2. **Query Sanitization**: Queries logged without sensitive values
3. **Access Logging**: All tool usage logged with context
4. **Error Sanitization**: Error messages sanitized for logs

## Performance Considerations

### Connection Management
- Connection pooling with configurable limits
- Automatic connection health checks
- Graceful connection recovery

### Query Optimization
- Default row limits to prevent large result sets
- Query timeout enforcement
- Result streaming for large datasets

### Caching Strategy
- Schema information caching
- Query plan caching (future)
- Connection reuse optimization

## Usage Examples

### Basic Table Exploration
```bash
# List all tables
echo '{"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "list_tables"}, "id": 1}' | npm start

# Get table schema
echo '{"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "describe_table", "arguments": {"table_name": "users"}}, "id": 2}' | npm start

# Query specific data
echo '{"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "execute_select", "arguments": {"query": "SELECT id, name FROM users LIMIT 5"}}, "id": 3}' | npm start
```

### Parameterized Queries
```bash
# Search with parameters
echo '{"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "execute_select", "arguments": {"query": "SELECT * FROM orders WHERE customer_id = $1 AND status = $2", "parameters": [123, "active"]}}, "id": 4}' | npm start
```