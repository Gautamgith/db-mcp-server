# PostgreSQL MCP Server

A unified, production-ready Model Context Protocol (MCP) server for PostgreSQL databases with comprehensive security features and flexible authentication modes.

## Overview

This MCP server provides secure, controlled access to PostgreSQL databases running on AWS RDS. It supports both standard password authentication and AWS IAM authentication, making it suitable for local development and production deployments on AWS infrastructure.

## Key Features

### **Security First**
- ✅ **SQL Injection Prevention** - Multi-layer validation with parameterized queries
- ✅ **Query Pattern Allowlisting** - Predefined secure patterns for common operations
- ✅ **Rate Limiting** - Configurable request throttling (100 req/min default)
- ✅ **Complexity Analysis** - Automatic query complexity scoring and limits
- ✅ **Input Validation** - Comprehensive parameter sanitization
- ✅ **Audit Logging** - Complete execution trail with structured JSON logs

### **Flexible Authentication**
- 🔐 **Standard Mode** - Password-based authentication for local development
- 🔐 **IAM Mode** - AWS IAM authentication with automatic token rotation for production
- ⚙️ **Easy Toggle** - Switch modes via `USE_IAM_AUTH` environment variable

### **Comprehensive Toolset**
- 📋 **Database Introspection** - List tables, describe schemas, analyze relationships
- 🔍 **Query Execution** - Parameterized and pattern-based secure queries
- 🔬 **Security Analysis** - Validate syntax, analyze complexity, check patterns
- 📊 **System Monitoring** - Connection health, security status, rate limits

## Architecture

See [ARCHITECTURE.md](./ARCHITECTURE.md) for detailed technical decisions and design rationale.

## Quick Start

### Prerequisites

- Node.js 18+
- PostgreSQL database (local or AWS RDS)
- For AWS IAM mode: EC2 instance with appropriate IAM role

### Installation

```bash
npm install
npm run build
```

### Configuration

Create a `.env` file:

```env
# Database Configuration
DB_HOST=your-database-host.com
DB_PORT=5432
DB_NAME=your_database
DB_USER=your_database_user
DB_PASSWORD=your_password          # Only for standard mode
AWS_REGION=us-west-2

# Authentication Mode
USE_IAM_AUTH=false                 # Set to 'true' for IAM authentication

# Security Configuration (Optional)
RATE_LIMIT_REQUESTS=100           # Max requests per window
RATE_LIMIT_WINDOW_MS=60000        # Rate limit window (1 minute)
MAX_QUERY_SIZE=10000              # Max query length in characters
MAX_QUERY_COMPLEXITY_SCORE=20     # Max complexity score

# Server Configuration (Optional)
MCP_SERVER_NAME=postgresql-mcp
MCP_SERVER_VERSION=1.0.0
```

### Usage

#### Standard Mode (Local Development)
```bash
# Development with auto-reload
npm run dev

# Production
npm start
```

#### IAM Mode (AWS Production)
```bash
# Development
USE_IAM_AUTH=true npm run dev

# Production
USE_IAM_AUTH=true npm start
```

### Testing Connection

```bash
# Test standard connection
npm run test:connection

# Test IAM connection (requires AWS credentials)
npm run test:iam
```

## Available Tools

The server provides **10 comprehensive tools** for database operations:

### Database Introspection
- **`list_tables`** - List all tables in a schema
- **`describe_table`** - Get detailed table schema with columns, indexes, and foreign keys

### Query Execution
- **`execute_query`** - Execute parameterized SELECT queries with full security validation
- **`structured_query`** - Execute predefined secure query patterns

### Security & Analysis
- **`query_patterns`** - List all available secure query patterns
- **`analyze_query_complexity`** - Analyze query complexity without execution
- **`validate_query_syntax`** - Validate SQL syntax

### System Monitoring
- **`connection_health`** - Check database connection and authentication status
- **`security_status`** - Get security system configuration and limits
- **`rate_limit_status`** - Check current rate limiting status

See [FUNCTIONS.md](./FUNCTIONS.md) for detailed tool documentation with examples.

## Security Features

### Multi-Layer Protection

1. **Query Validation**
   - Pattern-based allowlisting
   - SQL injection detection
   - Parameterized query enforcement

2. **Execution Limits**
   - Rate limiting per client
   - Query complexity scoring
   - Result row limits (configurable 1-1000)
   - Query timeout enforcement

3. **Authentication Security**
   - No stored credentials in IAM mode
   - Automatic token rotation (15-minute validity)
   - Connection pool management

4. **Audit & Compliance**
   - Structured JSON logging
   - Query execution tracking
   - Performance metrics
   - Error categorization

### OWASP LLM Top 10 Compliance

This implementation addresses the OWASP Top 10 for LLM Applications:
- **8.2/10** overall security rating
- Superior to AWS native solutions (6.1/10)
- See [SECURITY_COMPARISON.md](./SECURITY_COMPARISON.md) for detailed analysis

## Development

### Project Structure
```
src/
├── index.ts                           # Unified server entry point
├── auth/
│   └── iam-auth.ts                   # IAM token management
├── database/
│   ├── config.ts                     # Configuration management
│   ├── connection.ts                 # Standard DB connection
│   ├── iam-connection.ts            # IAM DB connection
│   ├── queries.ts                    # Standard queries
│   └── iam-queries.ts               # IAM queries
├── logging/
│   └── logger.ts                     # Structured logging
├── security/
│   ├── query-validator.ts           # SQL injection protection
│   └── rate-limiter.ts              # Rate limiting & complexity
├── tools/
│   └── database-tools-unified.ts    # All MCP tools
├── types/
│   └── index.ts                      # TypeScript interfaces
└── test/
    ├── connection.ts                 # Connection test utility
    └── iam-connection.ts            # IAM test utility
```

### Build & Test

```bash
# Build TypeScript
npm run build

# Type checking
npm run typecheck

# Linting
npm run lint

# Test connections
npm run test:connection
npm run test:iam
```

### Git Workflow

```bash
git add .
git commit -m "feat: implement new feature"
git push
```

## Deployment

### AWS Production Deployment

For production deployment on AWS with Terraform and CI/CD:

1. **Infrastructure Setup**
   - See [SETUP.md](./SETUP.md) for AWS prerequisites
   - See [DEPLOYMENT.md](./DEPLOYMENT.md) for complete deployment guide

2. **Key Features**
   - Automated Terraform deployment
   - GitHub Actions CI/CD pipeline
   - MCP Inspector web interface (port 3000)
   - Centralized logging interface (port 8080)
   - CloudWatch integration

3. **Deployment Options**
   - Separate RDS creation for reusable database infrastructure
   - EC2-only deployment for existing databases

See deployment documentation for detailed instructions.

## Documentation

- **[ARCHITECTURE.md](./ARCHITECTURE.md)** - Technical decisions and design rationale
- **[FUNCTIONS.md](./FUNCTIONS.md)** - Detailed tool reference with examples
- **[SETUP.md](./SETUP.md)** - AWS infrastructure and configuration guide
- **[DEPLOYMENT.md](./DEPLOYMENT.md)** - Complete deployment guide with CI/CD
- **[TESTING_GUIDE.md](./TESTING_GUIDE.md)** - MCP Inspector testing procedures
- **[SECURITY_ARCHITECTURE.md](./SECURITY_ARCHITECTURE.md)** - Security framework and compliance
- **[SECURITY_COMPARISON.md](./SECURITY_COMPARISON.md)** - OWASP Top 10 assessment
- **[COMPARATIVE_ANALYSIS.md](./COMPARATIVE_ANALYSIS.md)** - vs AWS native solutions
- **[ISO_PROJECT_PROPOSAL.md](./ISO_PROJECT_PROPOSAL.md)** - Enterprise project proposal
- **[TODO.md](./TODO.md)** - Future enhancements

## Migration from Previous Versions

If upgrading from a previous version with multiple server variants:

**Before:** 3 separate servers
- `npm run dev` / `npm run dev:iam` / `npm run dev:secure`

**After:** 1 unified server
- `npm run dev` (standard mode)
- `USE_IAM_AUTH=true npm run dev` (IAM mode)

All security features are now enabled by default. No functionality has been removed.

## Contributing

1. Follow conventional commit messages (`feat:`, `fix:`, `docs:`, etc.)
2. Ensure all tests pass (`npm test`)
3. Update documentation for new features
4. Run linting before commits (`npm run lint`)

## License

MIT

## Support

For issues, questions, or contributions, please open a GitHub issue with:
- Clear description of the problem
- Environment details (Node version, OS, deployment type)
- Steps to reproduce
- Expected vs actual behavior
