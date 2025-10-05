# PostgreSQL MCP Server Infrastructure (using existing network resources)
terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# Data sources for existing network resources
data "aws_vpc" "existing" {
  id = var.vpc_id
}

data "aws_subnet" "public" {
  id = var.public_subnet_id
}

data "aws_subnet" "private" {
  count = length(var.private_subnet_ids)
  id    = var.private_subnet_ids[count.index]
}

data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }
}

data "aws_caller_identity" "current" {}

# Security Groups
resource "aws_security_group" "mcp_server_sg" {
  name_prefix = "mcp-server-${var.environment}-"
  description = "Security group for MCP Server EC2 instance"
  vpc_id      = data.aws_vpc.existing.id

  # SSH access
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.allowed_ssh_cidrs
  }

  # MCP Inspector web interface
  ingress {
    from_port   = 3000
    to_port     = 3000
    protocol    = "tcp"
    cidr_blocks = var.allowed_web_cidrs
  }

  # Logging interface
  ingress {
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = var.allowed_web_cidrs
  }

  # HTTPS
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = var.allowed_web_cidrs
  }

  # HTTP (for Let's Encrypt)
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # All outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "mcp-server-sg-${var.environment}"
    Environment = var.environment
  }
}

resource "aws_security_group" "rds_sg" {
  name_prefix = "mcp-rds-${var.environment}-"
  description = "Security group for RDS PostgreSQL instance"
  vpc_id      = data.aws_vpc.existing.id

  # PostgreSQL access from MCP server
  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.mcp_server_sg.id]
  }

  tags = {
    Name        = "mcp-rds-sg-${var.environment}"
    Environment = var.environment
  }
}

# IAM Role for EC2 Instance
resource "aws_iam_role" "mcp_server_role" {
  name = "mcp-server-role-${var.environment}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Environment = var.environment
  }
}

resource "aws_iam_role_policy" "mcp_server_policy" {
  name = "mcp-server-policy-${var.environment}"
  role = aws_iam_role.mcp_server_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "rds-db:connect"
        ]
        Resource = [
          "arn:aws:rds-db:${var.aws_region}:${data.aws_caller_identity.current.account_id}:dbuser:${aws_db_instance.postgres.identifier}/${var.db_iam_username}"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogStreams"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "cloudwatch:PutMetricData"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_instance_profile" "mcp_server_profile" {
  name = "mcp-server-profile-${var.environment}"
  role = aws_iam_role.mcp_server_role.name
}

# RDS Subnet Group (using existing private subnets)
resource "aws_db_subnet_group" "postgres_subnet_group" {
  name       = "mcp-postgres-subnet-group-${var.environment}"
  subnet_ids = var.private_subnet_ids

  tags = {
    Name        = "MCP PostgreSQL Subnet Group"
    Environment = var.environment
  }
}

# RDS PostgreSQL Instance
resource "aws_db_instance" "postgres" {
  identifier = "mcp-postgres-${var.environment}"

  # Engine configuration
  engine         = "postgres"
  engine_version = "15.4"
  instance_class = var.rds_instance_class

  # Storage configuration
  allocated_storage     = var.rds_allocated_storage
  max_allocated_storage = var.rds_max_allocated_storage
  storage_type          = "gp3"
  storage_encrypted     = true

  # Database configuration
  db_name  = var.db_name
  username = var.db_master_username
  password = var.db_master_password

  # Network configuration
  db_subnet_group_name   = aws_db_subnet_group.postgres_subnet_group.name
  vpc_security_group_ids = [aws_security_group.rds_sg.id]
  publicly_accessible    = false

  # IAM database authentication
  iam_database_authentication_enabled = true

  # Backup configuration
  backup_retention_period = 7
  backup_window          = "03:00-04:00"
  maintenance_window     = "sun:04:00-sun:05:00"

  # Monitoring
  monitoring_interval = 60
  monitoring_role_arn = aws_iam_role.rds_monitoring_role.arn

  # Deletion protection
  deletion_protection = var.enable_deletion_protection
  skip_final_snapshot = !var.enable_deletion_protection

  tags = {
    Name        = "mcp-postgres-${var.environment}"
    Environment = var.environment
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
}

resource "aws_iam_role_policy_attachment" "rds_monitoring_policy" {
  role       = aws_iam_role.rds_monitoring_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
}

# EC2 Instance
resource "aws_instance" "mcp_server" {
  ami                    = data.aws_ami.amazon_linux.id
  instance_type          = var.ec2_instance_type
  key_name              = var.ec2_key_pair_name
  vpc_security_group_ids = [aws_security_group.mcp_server_sg.id]
  subnet_id             = data.aws_subnet.public.id
  iam_instance_profile  = aws_iam_instance_profile.mcp_server_profile.name

  user_data = base64encode(templatefile("${path.module}/user_data.sh", {
    db_host        = aws_db_instance.postgres.endpoint
    db_name        = var.db_name
    db_iam_user    = var.db_iam_username
    aws_region     = var.aws_region
    github_repo    = var.github_repo_url
    domain_name    = var.domain_name
    environment    = var.environment
  }))

  root_block_device {
    volume_type = "gp3"
    volume_size = 20
    encrypted   = true
  }

  tags = {
    Name        = "mcp-server-${var.environment}"
    Environment = var.environment
    Purpose     = "PostgreSQL MCP Server"
  }
}

# CloudWatch Log Groups
resource "aws_cloudwatch_log_group" "mcp_server_logs" {
  name              = "/aws/ec2/mcp-server/${var.environment}"
  retention_in_days = 30

  tags = {
    Environment = var.environment
    Application = "MCP Server"
  }
}

resource "aws_cloudwatch_log_group" "mcp_audit_logs" {
  name              = "/aws/ec2/mcp-server/${var.environment}/audit"
  retention_in_days = 90

  tags = {
    Environment = var.environment
    Application = "MCP Server Audit"
  }
}