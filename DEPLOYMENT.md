# Deployment Guide

This guide covers deploying the PostgreSQL MCP Server to AWS EC2 with complete CI/CD pipeline, MCP Inspector interface, and centralized logging.

## Architecture Overview

```
┌─────────────────┐    GitHub     ┌──────────────────┐    Private IP    ┌─────────────────┐
│   GitHub Repo   │ ────Actions──►│   EC2 Instance   │ ◄──────────────► │  RDS PostgreSQL │
│                 │               │   (MCP Server)   │                  │   (IAM Auth)    │
└─────────────────┘               └──────────────────┘                  └─────────────────┘
                                           │
                                           ▼
                                  ┌──────────────────┐
                                  │   Web Interfaces │
                                  │  :3000 Inspector │
                                  │  :8080 Logs      │
                                  └──────────────────┘
```

## Prerequisites

### 1. AWS Infrastructure
- **Existing VPC** with public and private subnets
- **EC2 Key Pair** for SSH access
- **IAM Permissions** for Terraform and deployment

### 2. GitHub Repository
- **Repository Secrets** configured for AWS access
- **Branch Protection** rules (recommended)

### 3. Domain (Optional)
- **DNS Configuration** for custom domain
- **SSL Certificate** (Let's Encrypt supported)

## Step 1: Infrastructure Deployment

### Configure Terraform Variables

Create `terraform.tfvars`:

```hcl
# AWS Configuration
aws_region = "us-west-2"
environment = "dev"

# Existing Network Resources
vpc_id = "vpc-xxxxxxxxx"
public_subnet_id = "subnet-xxxxxxxxx"
private_subnet_ids = ["subnet-yyyyyyyyy", "subnet-zzzzzzzzz"]

# Security Configuration
allowed_ssh_cidrs = ["10.0.0.0/8"]
allowed_web_cidrs = ["10.0.0.0/8"]

# EC2 Configuration
ec2_instance_type = "t3.medium"
ec2_key_pair_name = "your-key-pair"

# RDS Configuration
rds_instance_class = "db.t3.micro"
db_master_password = "your-secure-password"
db_iam_username = "mcp_server"

# Application Configuration
github_repo_url = "https://github.com/your-org/postgresql-mcp.git"
domain_name = "mcp.yourdomain.com"  # Optional
```

### Deploy Infrastructure

```bash
cd infrastructure/terraform

# Initialize Terraform
terraform init

# Plan deployment
terraform plan -var-file="terraform.tfvars"

# Apply infrastructure
terraform apply -var-file="terraform.tfvars"
```

### Infrastructure Outputs

After deployment, note these important outputs:

```bash
# Get deployment information
terraform output

# Key outputs:
# - ec2_public_ip: Public IP of EC2 instance
# - rds_endpoint: PostgreSQL database endpoint
# - mcp_inspector_url: http://IP:3000
# - logging_interface_url: http://IP:8080
```

## Step 2: Database Setup

### Configure IAM Database User

```bash
# Connect to RDS instance as master user
psql -h <rds_endpoint> -U postgres -d mcpserver

# Run the setup script
\i deployment/scripts/setup-db-user.sql

# Verify IAM user creation
\du mcp_server
```

### Test IAM Authentication

```bash
# SSH to EC2 instance
ssh -i ~/.ssh/your-key.pem ec2-user@<ec2_public_ip>

# Test IAM token generation
aws rds generate-db-auth-token \
  --hostname <rds_endpoint> \
  --port 5432 \
  --region us-west-2 \
  --username mcp_server
```

## Step 3: GitHub Actions Setup

### Required Secrets

Configure these secrets in your GitHub repository:

```
AWS_ACCESS_KEY_ID         # AWS access key for deployment
AWS_SECRET_ACCESS_KEY     # AWS secret key for deployment
EC2_SSH_PRIVATE_KEY      # Private key for EC2 SSH access
SNYK_TOKEN               # Security scanning (optional)
```

### Repository Settings

1. **Branch Protection Rules**:
   - Require pull request reviews
   - Require status checks to pass
   - Require branches to be up to date

2. **Environment Secrets**:
   - `development`: For dev deployments
   - `staging`: For staging deployments
   - `production`: For prod deployments

### Deployment Workflow

The CI/CD pipeline automatically:

1. **Tests & Builds** on every push/PR
2. **Security Scans** dependencies and code
3. **Deploys to Dev** on push to `develop` branch
4. **Deploys to Prod** on push to `main` branch

Manual deployment available via workflow dispatch.

## Step 4: Web Interfaces

### MCP Inspector (Port 3000)

Accessible at: `http://<ec2_public_ip>/inspector/`

**Features:**
- Interactive tool testing
- Real-time query execution
- Schema exploration
- Security feature testing

**Usage:**
1. Open in browser
2. Connect to MCP server
3. Test available tools
4. Monitor query execution

### Logging Interface (Port 8080)

Accessible at: `http://<ec2_public_ip>/logs/`

**Features:**
- Real-time log streaming
- Multiple log source support
- Advanced filtering and search
- System status monitoring

**Available Log Sources:**
- MCP Server Application logs
- MCP Inspector logs
- System messages
- Nginx access/error logs
- Custom application logs

## Step 5: SSL Configuration (Optional)

### Automatic SSL with Let's Encrypt

```bash
# SSH to EC2 instance
ssh -i ~/.ssh/your-key.pem ec2-user@<ec2_public_ip>

# Configure domain in nginx
sudo nano /etc/nginx/conf.d/mcp-server.conf

# Request SSL certificate
sudo certbot --nginx -d your-domain.com

# Test auto-renewal
sudo certbot renew --dry-run
```

## Step 6: Monitoring & Maintenance

### CloudWatch Integration

Automatic metrics collection for:
- **System Metrics**: CPU, Memory, Disk usage
- **Application Logs**: Structured JSON logs
- **Custom Metrics**: Query performance, error rates

### Log Retention

- **Application logs**: 30 days
- **Audit logs**: 90 days
- **System logs**: 7 days

### Backup Strategy

- **RDS Automated Backups**: 7 days retention
- **Daily Snapshots**: Custom backup window
- **Point-in-time Recovery**: Available

## Operational Commands

### Deployment Operations

```bash
# Manual deployment
ssh ec2-user@<ip> '/opt/mcp-server/deploy.sh'

# Service management
sudo systemctl status mcp-server
sudo systemctl restart mcp-server
sudo systemctl restart mcp-inspector

# View logs
sudo journalctl -u mcp-server -f
sudo journalctl -u mcp-inspector -f
```

### Health Checks

```bash
# Check service status
curl http://<ip>/inspector/
curl http://<ip>/logs/api/system/status

# Database connectivity test
cd /opt/mcp-server && npm run test:iam
```

### Troubleshooting

```bash
# Check EC2 instance logs
sudo tail -f /var/log/cloud-init-output.log

# Check application logs
sudo journalctl -u mcp-server --no-pager -n 50

# Check database connectivity
aws rds describe-db-instances --db-instance-identifier mcp-postgres-dev

# Test IAM authentication
aws rds generate-db-auth-token \
  --hostname <endpoint> --port 5432 \
  --region us-west-2 --username mcp_server
```

## Security Considerations

### Network Security
- **VPC Isolation**: All resources in private network
- **Security Groups**: Minimal required access
- **SSH Key Management**: Rotate keys regularly

### Application Security
- **IAM Authentication**: No stored database credentials
- **Rate Limiting**: 100 requests/minute default
- **SQL Injection Protection**: Multiple validation layers
- **Input Sanitization**: All user inputs validated

### Monitoring Security
- **Failed Authentication Attempts**: Logged and monitored
- **Suspicious Query Patterns**: Automated detection
- **Access Logging**: Complete audit trail

## Performance Tuning

### EC2 Instance Sizing
- **t3.medium**: Good for development/testing
- **t3.large**: Recommended for production
- **c5.large**: For CPU-intensive workloads

### RDS Configuration
- **Connection Pooling**: Configured in application
- **Read Replicas**: For high-read workloads
- **Performance Insights**: Enable for monitoring

### Application Tuning
- **Query Complexity Limits**: Configurable thresholds
- **Connection Pool Size**: Adjust based on load
- **Rate Limiting**: Tune based on usage patterns

## Disaster Recovery

### Backup Strategy
- **Automated RDS Backups**: Daily
- **Configuration Backups**: In git repository
- **Deployment Artifacts**: Stored in GitHub

### Recovery Procedures
1. **Infrastructure**: Redeploy via Terraform
2. **Database**: Restore from RDS backup
3. **Application**: Deploy from GitHub
4. **Configuration**: Restore from git

**Recovery Time Objective (RTO)**: < 30 minutes
**Recovery Point Objective (RPO)**: < 24 hours

This deployment provides a production-ready, secure, and maintainable PostgreSQL MCP server with comprehensive monitoring and automation.