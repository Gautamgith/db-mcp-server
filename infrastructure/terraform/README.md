# Terraform Infrastructure for PostgreSQL MCP Server

This directory contains Terraform configurations for deploying the PostgreSQL MCP Server to AWS.

## Deployment Options

### Option 1: Full Stack (EC2 + RDS) - For Testing/POC

**Use when**: You need a complete environment for testing, development, or proof-of-concept.

**Includes**:
- EC2 instance running MCP server
- New RDS PostgreSQL instance
- All necessary security groups and IAM roles
- CloudWatch logging

**File**: `main.tf`

### Option 2: EC2-Only - For Production

**Use when**: Connecting to existing staging or production RDS instances.

**Includes**:
- EC2 instance running MCP server only
- Connects to your existing RDS instance
- Security groups and IAM roles for EC2
- CloudWatch logging

**File**: `main-ec2-only.tf`

### Option 3: RDS Module Only - For Shared Infrastructure

**Use when**: Creating a shared RDS instance that multiple MCP servers will connect to.

**Location**: `modules/rds/`

---

## Quick Start

### Full Stack Deployment (Testing/POC)

```bash
# 1. Create terraform.tfvars
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your values

# 2. Initialize Terraform
terraform init

# 3. Review plan
terraform plan -var-file="terraform.tfvars"

# 4. Deploy
terraform apply -var-file="terraform.tfvars"

# 5. Get outputs
terraform output
```

### EC2-Only Deployment (Production)

```bash
# 1. Create variables file
cp variables-ec2-only.tfvars.example variables-ec2-only.tfvars
# Edit with your existing RDS details

# 2. Initialize Terraform
terraform init

# 3. Use EC2-only configuration
terraform plan \
  -var-file="variables-ec2-only.tfvars" \
  main-ec2-only.tf

# 4. Deploy
terraform apply \
  -var-file="variables-ec2-only.tfvars" \
  main-ec2-only.tf
```

---

## File Structure

```
infrastructure/terraform/
├── main.tf                          # Full stack (EC2 + RDS)
├── main-ec2-only.tf                # EC2 only (use existing RDS)
├── variables.tf                     # Variable definitions
├── outputs.tf                       # Output definitions
├── user_data.sh                     # EC2 bootstrap script
├── terraform.tfvars.example         # Example for full stack
├── variables-ec2-only.tfvars.example # Example for EC2-only
└── modules/
    └── rds/                         # Reusable RDS module
        ├── main.tf
        ├── variables.tf
        ├── outputs.tf
        └── README.md
```

---

## Prerequisites

### AWS Resources

1. **VPC with Subnets**:
   - At least 1 public subnet (for EC2)
   - At least 2 private subnets (for RDS, if deploying)

2. **EC2 Key Pair**:
   - Create via AWS Console or CLI
   - Used for SSH access

3. **IAM Permissions**:
   - EC2: create instances, security groups
   - RDS: create instances (if full stack)
   - IAM: create roles and policies
   - CloudWatch: create log groups

### Tools Required

- Terraform >= 1.0
- AWS CLI configured
- SSH key pair

---

## Configuration Guide

### Full Stack Configuration

Required variables in `terraform.tfvars`:

```hcl
# AWS Configuration
aws_region  = "us-west-2"
environment = "dev"

# Network (use your existing VPC)
vpc_id            = "vpc-xxxxxxxxx"
public_subnet_id  = "subnet-xxxxxxxxx"
private_subnet_ids = ["subnet-yyyyyyyyy", "subnet-zzzzzzzzz"]

# Security
allowed_ssh_cidrs = ["10.0.0.0/8"]
allowed_web_cidrs = ["10.0.0.0/8"]

# EC2
ec2_instance_type = "t3.medium"
ec2_key_pair_name = "your-key-pair"

# RDS
rds_instance_class  = "db.t3.micro"
db_master_password  = "SecurePassword123!"  # Use secrets manager
db_iam_username     = "mcp_server"

# Application
github_repo_url = "https://github.com/your-org/postgresql-mcp.git"
domain_name     = ""  # Optional
```

### EC2-Only Configuration

Required variables in `variables-ec2-only.tfvars`:

```hcl
# AWS Configuration
aws_region  = "us-west-2"
environment = "prod"

# Network
vpc_id           = "vpc-xxxxxxxxx"
public_subnet_id = "subnet-xxxxxxxxx"

# Security
allowed_ssh_cidrs = ["10.0.0.0/8"]
allowed_web_cidrs = ["10.0.0.0/8"]

# EC2
ec2_instance_type = "t3.medium"
ec2_key_pair_name = "your-key-pair"

# Existing RDS (from your staging/production environment)
rds_endpoint     = "your-rds.us-west-2.rds.amazonaws.com:5432"
rds_resource_id  = "db-XXXXXXXXXXXXXXX"  # From RDS console
db_name          = "your_database"
db_iam_username  = "mcp_server"

# Application
github_repo_url = "https://github.com/your-org/postgresql-mcp.git"
```

---

## Post-Deployment Steps

### 1. Get RDS Resource ID (EC2-Only Deployments)

```bash
# Via AWS CLI
aws rds describe-db-instances \
  --db-instance-identifier your-rds-instance \
  --query 'DBInstances[0].DbiResourceId' \
  --output text

# Output: db-XXXXXXXXXXXXXXX
```

### 2. Configure IAM Database User

```bash
# SSH to EC2 instance
ssh -i ~/.ssh/your-key.pem ec2-user@<ec2_public_ip>

# Connect to RDS
psql -h <rds_endpoint> -U postgres -d <database_name>

# Run setup script
\i /opt/mcp-server/deployment/scripts/setup-db-user.sql

# Verify
\du mcp_server
```

### 3. Test IAM Authentication

```bash
# On EC2 instance
cd /opt/mcp-server
npm run test:iam
```

### 4. Access Web Interfaces

```bash
# Get URLs from terraform
terraform output mcp_inspector_url
terraform output logging_interface_url

# Open in browser
http://<ec2_ip>:3000  # MCP Inspector
http://<ec2_ip>:8080  # Logging Interface
```

---

## Common Workflows

### Deploy to Development

```bash
# Full stack with new RDS
terraform workspace new dev
terraform apply -var-file="terraform-dev.tfvars"
```

### Deploy to Staging (Existing RDS)

```bash
# EC2-only, connect to existing staging RDS
terraform workspace new staging
terraform apply \
  -var-file="variables-staging.tfvars" \
  main-ec2-only.tf
```

### Deploy to Production (Existing RDS)

```bash
# EC2-only, connect to existing production RDS
terraform workspace new prod
terraform apply \
  -var-file="variables-prod.tfvars" \
  main-ec2-only.tf
```

### Update MCP Server Code

```bash
# SSH to instance
ssh -i ~/.ssh/key.pem ec2-user@<ip>

# Pull latest code
cd /opt/mcp-server
git pull

# Rebuild and restart
npm install
npm run build
sudo systemctl restart mcp-server
```

---

## Security Best Practices

### Network Security

1. **Use Private Subnets for RDS**: Never expose RDS publicly
2. **Restrict SSH Access**: Use specific IP ranges, not 0.0.0.0/0
3. **Restrict Web Access**: Limit to corporate network or VPN
4. **Use VPC Endpoints**: For AWS services (S3, CloudWatch, etc.)

### IAM Security

1. **Use IAM Authentication**: No database passwords in code
2. **Least Privilege**: EC2 role only needs `rds-db:connect`
3. **Rotate Tokens**: Automatic with IAM (15-minute tokens)
4. **Audit Access**: CloudWatch logs all authentication attempts

### RDS Security

1. **Enable Encryption**: Storage encrypted by default
2. **Enable Deletion Protection**: For production databases
3. **Regular Backups**: 7-14 day retention
4. **Multi-AZ**: For production workloads
5. **Performance Insights**: Monitor query performance

---

## Monitoring

### CloudWatch Logs

Automatically created log groups:
- `/aws/ec2/mcp-server/{env}` - Application logs (30 days)
- `/aws/ec2/mcp-server/{env}/audit` - Audit logs (90 days)
- `/aws/rds/instance/mcp-postgres-{env}/postgresql` - RDS logs

### Metrics to Monitor

- **EC2**: CPU, Memory, Disk, Network
- **RDS**: Connections, CPU, Storage, IOPS
- **Application**: Query rate, error rate, response time

### Recommended Alarms

```hcl
# EC2 CPU > 80%
# RDS CPU > 80%
# RDS Free Storage < 10GB
# RDS Connections > 80% of max
# Application Error Rate > 5%
```

---

## Cost Optimization

### Development/Testing

```hcl
ec2_instance_type      = "t3.small"    # $0.0208/hour
rds_instance_class     = "db.t3.micro" # $0.017/hour
multi_az               = false
deletion_protection    = false
backup_retention_period = 3
```

**Monthly cost**: ~$30-40

### Production

```hcl
ec2_instance_type      = "t3.medium"   # $0.0416/hour
rds_instance_class     = "db.t3.small" # $0.034/hour
multi_az               = true          # 2x RDS cost
deletion_protection    = true
backup_retention_period = 14
```

**Monthly cost**: ~$110-130

---

## Troubleshooting

### EC2 Instance Won't Start

```bash
# Check user data execution
ssh ec2-user@<ip>
sudo tail -f /var/log/cloud-init-output.log
```

### Can't Connect to RDS

```bash
# Test IAM token generation
aws rds generate-db-auth-token \
  --hostname <endpoint> \
  --port 5432 \
  --region us-west-2 \
  --username mcp_server

# Check security groups
aws ec2 describe-security-groups \
  --group-ids sg-xxxxx

# Test connectivity
telnet <rds-endpoint> 5432
```

### MCP Server Not Responding

```bash
# Check service status
sudo systemctl status mcp-server

# Check logs
sudo journalctl -u mcp-server -f

# Restart service
sudo systemctl restart mcp-server
```

### Terraform Errors

```bash
# State issues
terraform init -upgrade

# Lock issues
terraform force-unlock <lock-id>

# Import existing resources
terraform import aws_instance.mcp_server i-xxxxx
```

---

## Cleanup

### Destroy Full Stack

```bash
# This will delete EC2 AND RDS
terraform destroy -var-file="terraform.tfvars"
```

### Destroy EC2-Only

```bash
# This only deletes EC2, RDS is untouched
terraform destroy \
  -var-file="variables-ec2-only.tfvars" \
  main-ec2-only.tf
```

⚠️ **Warning**: Destroying RDS will delete all data. Ensure backups exist!

---

## Additional Resources

- [DEPLOYMENT.md](../../DEPLOYMENT.md) - Complete deployment guide
- [SETUP.md](../../SETUP.md) - AWS configuration and IAM setup
- [modules/rds/README.md](modules/rds/README.md) - RDS module documentation
- [Terraform AWS Provider Docs](https://registry.terraform.io/providers/hashicorp/aws/latest/docs)

---

## Support

For issues or questions:
1. Check [DEPLOYMENT.md](../../DEPLOYMENT.md) troubleshooting section
2. Review CloudWatch logs
3. Verify IAM permissions
4. Check security group rules
5. Open GitHub issue with details
