# Setup Guide

## Prerequisites

### System Requirements
- **Node.js**: Version 18 or higher
- **npm**: Latest stable version
- **TypeScript**: Installed globally or via project dependencies

### AWS Infrastructure
- **EC2 Instance**: Running in the same VPC as RDS
- **RDS PostgreSQL**: Instance with IAM authentication enabled
- **VPC Configuration**: Proper security groups and network ACLs
- **IAM Role**: Attached to EC2 instance with RDS permissions

## AWS Configuration

### 1. RDS Setup
```bash
# Enable IAM database authentication on your RDS instance
aws rds modify-db-instance \
  --db-instance-identifier your-instance-id \
  --enable-iam-database-authentication \
  --apply-immediately
```

### 2. IAM Role for EC2
Create an IAM role with the following policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "rds-db:connect"
      ],
      "Resource": [
        "arn:aws:rds-db:region:account-id:dbuser:db-instance-id/db-username"
      ]
    }
  ]
}
```

### 3. Database User Setup
Connect to your PostgreSQL database and create an IAM user:

```sql
-- Create IAM user
CREATE USER your_iam_username;

-- Grant necessary permissions (read-only)
GRANT CONNECT ON DATABASE your_database TO your_iam_username;
GRANT USAGE ON SCHEMA public TO your_iam_username;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO your_iam_username;
GRANT SELECT ON ALL SEQUENCES IN SCHEMA public TO your_iam_username;

-- Grant permissions on future tables
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO your_iam_username;
```

## Project Setup

### 1. Clone and Install
```bash
git clone <repository-url>
cd postgresql-mcp-server
npm install
```

### 2. Environment Configuration
Create a `.env` file in the project root:

```env
# Database Configuration
DB_HOST=your-rds-endpoint.region.rds.amazonaws.com
DB_PORT=5432
DB_NAME=your_database_name
DB_USER=your_iam_username

# AWS Configuration
AWS_REGION=us-west-2

# MCP Configuration
MCP_SERVER_NAME=postgresql-mcp
MCP_SERVER_VERSION=1.0.0

# Logging Configuration
LOG_LEVEL=info
LOG_FORMAT=json

# Development Configuration
NODE_ENV=production
```

### 3. Build the Project
```bash
# Development build
npm run build

# Development with watch mode
npm run dev
```

## Security Group Configuration

### EC2 Security Group
```bash
# Outbound rule for PostgreSQL
aws ec2 authorize-security-group-egress \
  --group-id sg-your-ec2-sg \
  --protocol tcp \
  --port 5432 \
  --source-group sg-your-rds-sg
```

### RDS Security Group
```bash
# Inbound rule from EC2
aws ec2 authorize-security-group-ingress \
  --group-id sg-your-rds-sg \
  --protocol tcp \
  --port 5432 \
  --source-group sg-your-ec2-sg
```

## Testing the Setup

### 1. Test Database Connection
```bash
# Test IAM authentication
npm run test:connection
```

### 2. Test MCP Server
```bash
# Start the server
npm start

# In another terminal, test with McpInspector
npx @modelcontextprotocol/inspector
```

### 3. Verify Tools
The following MCP tools should be available:
- `list_tables`
- `describe_table`
- `execute_select`

## Deployment

### 1. Production Build
```bash
npm run build
npm run start
```

### 2. Process Management
Use PM2 or similar for production deployment:

```bash
# Install PM2
npm install -g pm2

# Start with PM2
pm2 start dist/index.js --name postgresql-mcp

# Setup auto-restart
pm2 startup
pm2 save
```

### 3. Monitoring
```bash
# Check process status
pm2 status

# View logs
pm2 logs postgresql-mcp

# Monitor resource usage
pm2 monit
```

## Troubleshooting

### Common Issues

#### Connection Failed
```bash
# Check security groups
aws ec2 describe-security-groups --group-ids sg-your-ec2-sg sg-your-rds-sg

# Test network connectivity
telnet your-rds-endpoint.region.rds.amazonaws.com 5432
```

#### IAM Authentication Failed
```bash
# Verify EC2 instance role
aws sts get-caller-identity

# Check IAM permissions
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::account:role/your-role \
  --action-names rds-db:connect \
  --resource-arns arn:aws:rds-db:region:account:dbuser:instance/username
```

#### MCP Connection Issues
```bash
# Check MCP server logs
npm run logs

# Verify stdio communication
echo '{"jsonrpc": "2.0", "method": "initialize", "params": {}, "id": 1}' | npm start
```

### Debug Mode
Enable debug logging:

```env
LOG_LEVEL=debug
NODE_ENV=development
```

### Health Checks
The server includes basic health check endpoints:
- Database connectivity
- IAM token generation
- MCP tool availability

## Maintenance

### Regular Tasks
- **Token Rotation**: IAM tokens rotate automatically every 15 minutes
- **Log Rotation**: Configure log rotation based on your requirements
- **Connection Monitoring**: Monitor database connection pool health
- **Security Updates**: Keep dependencies updated

### Monitoring Metrics
- Connection pool utilization
- Query execution times
- Error rates
- IAM token refresh frequency