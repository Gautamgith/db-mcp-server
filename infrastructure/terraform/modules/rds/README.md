# RDS PostgreSQL Module

This Terraform module creates a PostgreSQL RDS instance with IAM authentication enabled, designed for use with the MCP Server.

## Features

- ✅ PostgreSQL 15.4 (configurable)
- ✅ IAM database authentication enabled
- ✅ Encrypted storage (KMS)
- ✅ Automated backups (7 days retention)
- ✅ Enhanced monitoring
- ✅ Performance Insights
- ✅ CloudWatch logs integration
- ✅ Multi-AZ support (optional)
- ✅ Deletion protection (configurable)

## Usage

### Basic Usage

```hcl
module "rds" {
  source = "./modules/rds"

  environment         = "prod"
  vpc_id              = "vpc-xxxxxxxxx"
  private_subnet_ids  = ["subnet-xxx", "subnet-yyy"]

  allowed_security_group_ids = [module.ec2.security_group_id]

  instance_class     = "db.t3.medium"
  master_password    = var.db_master_password  # From secrets

  deletion_protection = true
  multi_az            = true
}
```

### With Custom Configuration

```hcl
module "rds" {
  source = "./modules/rds"

  environment         = "dev"
  vpc_id              = var.vpc_id
  private_subnet_ids  = var.private_subnet_ids

  # Security
  allowed_security_group_ids = [aws_security_group.mcp_server.id]
  allowed_cidr_blocks        = ["10.0.0.0/16"]  # Optional: for debugging

  # Database Configuration
  instance_class       = "db.t3.micro"
  postgres_version     = "15.4"
  allocated_storage    = 20
  max_allocated_storage = 100
  database_name        = "mcpserver"
  master_username      = "postgres"
  master_password      = random_password.rds_password.result

  # Backup Configuration
  backup_retention_period = 14
  backup_window          = "03:00-04:00"
  maintenance_window     = "sun:04:00-sun:05:00"

  # Monitoring
  monitoring_interval         = 60
  enable_performance_insights = true

  # High Availability
  multi_az = false  # Set to true for production

  # Security
  deletion_protection = false  # Set to true for production
  kms_key_id          = aws_kms_key.rds.arn  # Optional: custom KMS key
}
```

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|----------|
| environment | Environment name (dev, staging, prod) | string | - | yes |
| vpc_id | ID of the VPC | string | - | yes |
| private_subnet_ids | List of private subnet IDs | list(string) | - | yes |
| allowed_security_group_ids | Security groups allowed to access RDS | list(string) | [] | no |
| allowed_cidr_blocks | CIDR blocks allowed to access RDS | list(string) | [] | no |
| instance_class | RDS instance class | string | `"db.t3.micro"` | no |
| postgres_version | PostgreSQL version | string | `"15.4"` | no |
| allocated_storage | Initial storage in GB | number | 20 | no |
| max_allocated_storage | Max storage for autoscaling in GB | number | 100 | no |
| database_name | Default database name | string | `"mcpserver"` | no |
| master_username | Master username | string | `"postgres"` | no |
| master_password | Master password | string | - | yes |
| backup_retention_period | Backup retention in days | number | 7 | no |
| backup_window | Preferred backup window | string | `"03:00-04:00"` | no |
| maintenance_window | Preferred maintenance window | string | `"sun:04:00-sun:05:00"` | no |
| monitoring_interval | Enhanced monitoring interval | number | 60 | no |
| enable_performance_insights | Enable Performance Insights | bool | true | no |
| multi_az | Enable Multi-AZ deployment | bool | false | no |
| deletion_protection | Enable deletion protection | bool | true | no |
| kms_key_id | KMS key ID for encryption | string | `""` | no |
| parameter_group_name | Custom parameter group name | string | `""` | no |
| auto_minor_version_upgrade | Enable auto minor version upgrades | bool | true | no |

## Outputs

| Name | Description |
|------|-------------|
| rds_endpoint | RDS instance endpoint (host:port) |
| rds_address | RDS instance address (host only) |
| rds_port | RDS instance port |
| rds_instance_id | RDS instance identifier |
| rds_resource_id | RDS resource ID for IAM policies |
| rds_arn | ARN of the RDS instance |
| rds_security_group_id | ID of the RDS security group |
| database_name | Name of the default database |
| master_username | Master username (sensitive) |
| monitoring_role_arn | ARN of the monitoring role |
| iam_auth_enabled | Whether IAM auth is enabled |

## Post-Deployment Steps

After deploying the RDS instance, you need to create the IAM database user:

```bash
# Connect to RDS as master user
psql -h <rds_endpoint> -U postgres -d mcpserver

# Run the setup script
\i deployment/scripts/setup-db-user.sql

# Verify IAM user creation
\du mcp_server
```

## IAM Policy for EC2 Instance

The EC2 instance running the MCP server needs this IAM policy to connect:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "rds-db:connect",
      "Resource": "arn:aws:rds-db:REGION:ACCOUNT_ID:dbuser:RESOURCE_ID/mcp_server"
    }
  ]
}
```

Replace:
- `REGION` with your AWS region
- `ACCOUNT_ID` with your AWS account ID
- `RESOURCE_ID` with the RDS resource ID (from outputs)

## Monitoring

### CloudWatch Logs

The module automatically creates log groups for:
- PostgreSQL logs (`/aws/rds/instance/mcp-postgres-{env}/postgresql`)
- Upgrade logs (`/aws/rds/instance/mcp-postgres-{env}/upgrade`)

### Enhanced Monitoring

Enabled by default with 60-second interval. Provides:
- OS-level metrics
- Process monitoring
- File system statistics

### Performance Insights

Enabled by default with 7-day retention. Provides:
- Query performance analysis
- Wait event analysis
- Database load monitoring

## Security Best Practices

1. **Use IAM Authentication**: No need to store database passwords
2. **Enable Encryption**: Storage is encrypted by default
3. **Restrict Access**: Use security groups, not CIDR blocks
4. **Enable Deletion Protection**: For production environments
5. **Regular Backups**: Configure appropriate retention period
6. **Multi-AZ**: Enable for production workloads
7. **Parameter Groups**: Use custom groups for specific tuning

## Cost Optimization

### Development/Testing
```hcl
instance_class              = "db.t3.micro"
multi_az                    = false
backup_retention_period     = 3
enable_performance_insights = false
deletion_protection         = false
```

### Production
```hcl
instance_class              = "db.t3.medium"  # or larger
multi_az                    = true
backup_retention_period     = 14
enable_performance_insights = true
deletion_protection         = true
```

## Maintenance

### Backup and Recovery

- Automated backups run during the backup window
- Point-in-time recovery available within retention period
- Final snapshot created before deletion (if deletion_protection = true)

### Upgrades

- Minor version upgrades automatic (if auto_minor_version_upgrade = true)
- Major version upgrades require manual intervention
- Maintenance occurs during maintenance window

### Monitoring Alerts

Recommended CloudWatch alarms:
- CPU utilization > 80%
- Free storage space < 10GB
- Database connections > 80% of max
- Replication lag (if Multi-AZ)

## Examples

See the parent `terraform` directory for complete examples:
- `main.tf` - Full deployment with EC2 and RDS
- `main-ec2-only.tf` - EC2 deployment using existing RDS

## Support

For issues or questions, refer to:
- [DEPLOYMENT.md](../../../../DEPLOYMENT.md) - Full deployment guide
- [SETUP.md](../../../../SETUP.md) - AWS configuration guide
- [README.md](../../../../README.md) - Project overview
