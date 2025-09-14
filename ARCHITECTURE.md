# PostgreSQL MCP Server - Architecture Decision Record

## Tech Stack Decisions

### Core Framework
- **MCP SDK**: `@modelcontextprotocol/sdk` (official TypeScript SDK)
- **Language**: TypeScript/Node.js
- **Transport**: stdio (for internal network communication)
- **Runtime**: Node.js 18+

### Database & AWS Integration
- **PostgreSQL Client**: `pg` (most mature and widely used)
- **AWS SDK**: `@aws-sdk/client-rds` (v3 - modern, tree-shakeable)
- **IAM Authentication**: `@aws-sdk/rds-signer` for token generation

### Development Tools
- **Build**: TypeScript compiler
- **Runtime Dev**: `tsx` for development
- **Linting**: ESLint with TypeScript rules
- **Package Manager**: npm

## Architecture Overview

```
┌─────────────────┐    stdio    ┌──────────────────┐    Private IP    ┌─────────────────┐
│   MCP Client    │ ◄─────────► │   MCP Server     │ ◄──────────────► │  RDS PostgreSQL │
│   (Internal)    │             │   (EC2 Instance) │                  │   (Private VPC) │
└─────────────────┘             └──────────────────┘                  └─────────────────┘
                                         │
                                         ▼
                                ┌──────────────────┐
                                │   AWS IAM Role   │
                                │   (for RDS auth) │
                                └──────────────────┘
```

## Key Design Decisions

### 1. MCP Transport: stdio
**Decision**: Use stdio transport instead of HTTP/WebSocket
**Rationale**: 
- Internal network usage - no need for HTTP overhead
- Simpler deployment and security model
- Better performance for internal tooling
**Tradeoffs**: Less flexible than HTTP but sufficient for internal use

### 2. Database Client: pg
**Decision**: Use `pg` library over alternatives like `postgres.js` or Prisma
**Rationale**:
- Most mature and stable PostgreSQL client
- Direct IAM authentication support
- Minimal overhead for our use case
- Extensive AWS RDS documentation
**Tradeoffs**: More verbose than modern alternatives but more reliable

### 3. AWS SDK v3
**Decision**: Use AWS SDK v3 instead of v2
**Rationale**:
- Tree-shakeable (smaller bundle size)
- Better TypeScript support
- Modern async/await patterns
- Long-term support
**Tradeoffs**: Slightly different API but better maintainability

### 4. IAM Authentication Strategy
**Decision**: Generate IAM auth tokens on-demand
**Rationale**:
- Tokens expire every 15 minutes - need fresh generation
- No credential storage required
- Leverages EC2 instance role
**Tradeoffs**: Additional network calls but better security

## Security Considerations

### SQL Injection Prevention
1. **Parameterized Queries**: All user inputs via prepared statements
2. **Query Allowlisting**: Predefined query patterns only
3. **Input Validation**: Schema validation for all parameters
4. **Read-Only User**: Database user with minimal privileges

### Network Security
- **Private Network**: No internet access required
- **VPC Security Groups**: Restrict PostgreSQL port access
- **IAM Roles**: No long-lived credentials

## Performance Considerations

### Connection Management
- **Connection Pooling**: Reuse connections efficiently
- **Connection Limits**: Respect RDS connection limits
- **Timeout Handling**: Graceful handling of network issues

### Query Optimization
- **Result Limits**: Default pagination for large datasets
- **Query Timeouts**: Prevent long-running queries
- **Caching Strategy**: Consider query result caching (future)

## Scalability Tradeoffs

### Current Architecture Benefits
- Simple deployment model
- Direct PostgreSQL access
- Low latency internal communication

### Current Architecture Limitations
- Single instance deployment
- No built-in load balancing
- Limited concurrent connection handling

### Future Considerations
- Multiple MCP server instances with connection pooling
- Query result caching layer
- Monitoring and observability integration

## Error Handling Strategy

1. **Database Errors**: Graceful degradation with meaningful messages
2. **IAM Token Issues**: Automatic retry with exponential backoff
3. **Network Issues**: Connection retry logic
4. **Input Validation**: Clear error messages for invalid queries

## Logging and Monitoring

- **Structured Logging**: JSON format for log aggregation
- **Query Logging**: All database interactions (with parameter sanitization)
- **Performance Metrics**: Query execution times
- **Error Tracking**: Comprehensive error logging

## Development Workflow

1. **Version Control**: Git with conventional commits
2. **Testing Strategy**: Unit tests for query builders, integration tests for database
3. **Documentation**: Inline code documentation + external docs
4. **Code Quality**: ESLint + TypeScript strict mode