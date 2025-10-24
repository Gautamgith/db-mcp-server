# RDS PostgreSQL Module
#
# This module creates a PostgreSQL RDS instance with IAM authentication enabled.
# Use this module when you want to create a standalone RDS instance that can be
# reused across multiple MCP server deployments.

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

data "aws_caller_identity" "current" {}

# RDS Subnet Group
resource "aws_db_subnet_group" "postgres_subnet_group" {
  name       = "mcp-postgres-subnet-group-${var.environment}"
  subnet_ids = var.private_subnet_ids

  tags = {
    Name        = "MCP PostgreSQL Subnet Group"
    Environment = var.environment
    ManagedBy   = "Terraform"
  }
}

# Security Group for RDS
resource "aws_security_group" "rds_sg" {
  name_prefix = "mcp-rds-${var.environment}-"
  description = "Security group for RDS PostgreSQL instance"
  vpc_id      = var.vpc_id

  # PostgreSQL access from allowed security groups
  dynamic "ingress" {
    for_each = var.allowed_security_group_ids
    content {
      from_port       = 5432
      to_port         = 5432
      protocol        = "tcp"
      security_groups = [ingress.value]
    }
  }

  # Optional: Allow from specific CIDR blocks (for debugging)
  dynamic "ingress" {
    for_each = var.allowed_cidr_blocks
    content {
      from_port   = 5432
      to_port     = 5432
      protocol    = "tcp"
      cidr_blocks = [ingress.value]
    }
  }

  tags = {
    Name        = "mcp-rds-sg-${var.environment}"
    Environment = var.environment
    ManagedBy   = "Terraform"
  }
}

# RDS Monitoring Role
resource "aws_iam_role" "rds_monitoring_role" {
  name = "rds-monitoring-role-${var.environment}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "monitoring.rds.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Environment = var.environment
    ManagedBy   = "Terraform"
  }
}

resource "aws_iam_role_policy_attachment" "rds_monitoring_policy" {
  role       = aws_iam_role.rds_monitoring_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
}

# RDS PostgreSQL Instance
resource "aws_db_instance" "postgres" {
  identifier = "mcp-postgres-${var.environment}"

  # Engine configuration
  engine         = "postgres"
  engine_version = var.postgres_version
  instance_class = var.instance_class

  # Storage configuration
  allocated_storage     = var.allocated_storage
  max_allocated_storage = var.max_allocated_storage
  storage_type          = "gp3"
  storage_encrypted     = true
  kms_key_id            = var.kms_key_id

  # Database configuration
  db_name  = var.database_name
  username = var.master_username
  password = var.master_password
  port     = 5432

  # Network configuration
  db_subnet_group_name   = aws_db_subnet_group.postgres_subnet_group.name
  vpc_security_group_ids = [aws_security_group.rds_sg.id]
  publicly_accessible    = false

  # IAM database authentication
  iam_database_authentication_enabled = true

  # Backup configuration
  backup_retention_period = var.backup_retention_period
  backup_window          = var.backup_window
  maintenance_window     = var.maintenance_window
  copy_tags_to_snapshot  = true

  # Monitoring
  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]
  monitoring_interval            = var.monitoring_interval
  monitoring_role_arn            = aws_iam_role.rds_monitoring_role.arn
  performance_insights_enabled   = var.enable_performance_insights
  performance_insights_retention_period = var.enable_performance_insights ? 7 : null

  # High Availability
  multi_az = var.multi_az

  # Deletion protection
  deletion_protection = var.deletion_protection
  skip_final_snapshot = !var.deletion_protection
  final_snapshot_identifier = var.deletion_protection ? "mcp-postgres-${var.environment}-final-snapshot-${formatdate("YYYY-MM-DD-hhmm", timestamp())}" : null

  # Parameter group
  parameter_group_name = var.parameter_group_name != "" ? var.parameter_group_name : "default.postgres${split(".", var.postgres_version)[0]}"

  # Auto minor version upgrade
  auto_minor_version_upgrade = var.auto_minor_version_upgrade

  tags = {
    Name        = "mcp-postgres-${var.environment}"
    Environment = var.environment
    ManagedBy   = "Terraform"
    Purpose     = "PostgreSQL database for MCP Server"
  }

  lifecycle {
    ignore_changes = [
      password,  # Ignore password changes after creation
      final_snapshot_identifier  # Dynamic timestamp causes issues
    ]
  }
}

# CloudWatch Log Groups for RDS
resource "aws_cloudwatch_log_group" "rds_postgresql_logs" {
  name              = "/aws/rds/instance/mcp-postgres-${var.environment}/postgresql"
  retention_in_days = 30

  tags = {
    Environment = var.environment
    Application = "MCP Server RDS"
    ManagedBy   = "Terraform"
  }
}

resource "aws_cloudwatch_log_group" "rds_upgrade_logs" {
  name              = "/aws/rds/instance/mcp-postgres-${var.environment}/upgrade"
  retention_in_days = 7

  tags = {
    Environment = var.environment
    Application = "MCP Server RDS"
    ManagedBy   = "Terraform"
  }
}
