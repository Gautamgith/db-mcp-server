# PostgreSQL MCP Server

A Model Context Protocol (MCP) server for PostgreSQL databases with IAM authentication support, designed for internal EC2 to RDS communication.

## Overview

This MCP server provides secure, controlled access to PostgreSQL databases running on AWS RDS through IAM authentication. It's designed for internal network usage where the MCP server runs on an EC2 instance and connects to RDS instances via private IP.

## Features

- **Phase 1**: Basic READ-only query functionality
- **Phase 2**: IAM authentication for RDS access
- **Phase 3**: Granular query controls with SQL injection protection
- **Phase 4**: Comprehensive query logging
- **Phase 5**: McpInspector integration testing

## Architecture

See [ARCHITECTURE.md](./ARCHITECTURE.md) for detailed technical decisions and design rationale.

## Prerequisites

- Node.js 18+
- AWS EC2 instance with appropriate IAM role
- RDS PostgreSQL instance in the same VPC
- IAM permissions for RDS token generation

## Installation

```bash
npm install
npm run build
```

## Configuration

Create a `.env` file with your database configuration:

```env
DB_HOST=your-rds-endpoint.region.rds.amazonaws.com
DB_PORT=5432
DB_NAME=your_database
DB_USER=your_iam_user
AWS_REGION=us-west-2
```

## Usage

### Development
```bash
npm run dev
```

### Production
```bash
npm start
```

### Testing
```bash
npm test
```

## MCP Tools

### Phase 1 - Basic Queries
- `query_tables` - List all tables in the database
- `query_schema` - Get schema information for a table
- `execute_query` - Execute a SELECT query with parameters

### Phase 2 - IAM Authentication
- Automatic IAM token generation and rotation
- EC2 instance role-based authentication

### Phase 3 - Advanced Security
- Parameterized query execution
- Query pattern allowlisting
- Input validation and sanitization

### Phase 4 - Logging
- Structured query logging
- Performance metrics
- Error tracking

## Security

- All queries use parameterized statements
- Read-only database operations only
- IAM-based authentication (no stored credentials)
- Private network communication only
- Query allowlisting and validation

## Development

### Project Structure
```
src/
├── index.ts          # MCP server entry point
├── database/         # Database connection and queries
├── tools/            # MCP tool definitions
├── auth/             # IAM authentication logic
├── logging/          # Logging infrastructure
└── types/            # TypeScript type definitions
```

### Git Workflow
```bash
git add .
git commit -m "feat: implement basic MCP server structure"
```

## Documentation

- [Architecture Decision Record](./ARCHITECTURE.md)
- [TODO and Future Tasks](./TODO.md)
- [Function Documentation](./FUNCTIONS.md)
- [Setup Guide](./SETUP.md)

## Contributing

1. Follow conventional commit messages
2. Ensure all tests pass
3. Update documentation for new features
4. Run linting before commits

## License

MIT