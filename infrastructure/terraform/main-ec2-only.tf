# EC2-Only Deployment for PostgreSQL MCP Server
#
# Use this configuration when you have an existing RDS instance
# and only want to deploy the EC2 instance running the MCP server.
#
# This is useful for:
# - Reusing a shared RDS instance across multiple environments
# - Deploying multiple MCP servers to the same database
# - Separating database lifecycle from application lifecycle

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

# Data sources for existing resources
data "aws_vpc" "existing" {
  id = var.vpc_id
}

data "aws_subnet" "public" {
  id = var.public_subnet_id
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

# Existing RDS instance data source
data "aws_db_instance" "existing_rds" {
  count                  = var.existing_rds_identifier != "" ? 1 : 0
  db_instance_identifier = var.existing_rds_identifier
}

# Security Group for MCP Server EC2
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
    description = "SSH access"
  }

  # MCP Server HTTP/SSE endpoint
  ingress {
    from_port   = 3000
    to_port     = 3000
    protocol    = "tcp"
    cidr_blocks = var.allowed_web_cidrs
    description = "MCP Server HTTP/SSE (OAuth authenticated)"
  }

  # Logging interface
  ingress {
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = var.allowed_web_cidrs
    description = "Logging Interface"
  }

  # HTTPS
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = var.allowed_web_cidrs
    description = "HTTPS"
  }

  # HTTP (for Let's Encrypt)
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTP (Let's Encrypt)"
  }

  # All outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "All outbound traffic"
  }

  tags = {
    Name        = "mcp-server-sg-${var.environment}"
    Environment = var.environment
    ManagedBy   = "Terraform"
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
    ManagedBy   = "Terraform"
  }
}

# IAM Policy for RDS IAM Authentication
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
          "arn:aws:rds-db:${var.aws_region}:${data.aws_caller_identity.current.account_id}:dbuser:${var.rds_resource_id}/${var.db_iam_username}"
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

  tags = {
    Environment = var.environment
    ManagedBy   = "Terraform"
  }
}

# EC2 Instance for MCP Server
resource "aws_instance" "mcp_server" {
  ami                    = data.aws_ami.amazon_linux.id
  instance_type          = var.ec2_instance_type
  key_name              = var.ec2_key_pair_name
  vpc_security_group_ids = [aws_security_group.mcp_server_sg.id]
  subnet_id             = data.aws_subnet.public.id
  iam_instance_profile  = aws_iam_instance_profile.mcp_server_profile.name

  user_data = base64encode(templatefile("${path.module}/user_data.sh", {
    db_host        = var.rds_endpoint
    db_name        = var.db_name
    db_iam_user    = var.db_iam_username
    aws_region     = var.aws_region
    github_repo    = var.github_repo_url
    domain_name    = var.domain_name
    environment    = var.environment
    oauth_enabled  = var.oauth_enabled
    oauth_issuer   = var.oauth_issuer
    oauth_audience = var.oauth_audience
    oauth_jwks_uri = var.oauth_jwks_uri
  }))

  root_block_device {
    volume_type = "gp3"
    volume_size = 20
    encrypted   = true
  }

  tags = {
    Name        = "mcp-server-${var.environment}"
    Environment = var.environment
    ManagedBy   = "Terraform"
    Purpose     = "PostgreSQL MCP Server"
  }

  lifecycle {
    create_before_destroy = true
  }
}

# CloudWatch Log Groups
resource "aws_cloudwatch_log_group" "mcp_server_logs" {
  name              = "/aws/ec2/mcp-server/${var.environment}"
  retention_in_days = 30

  tags = {
    Environment = var.environment
    Application = "MCP Server"
    ManagedBy   = "Terraform"
  }
}

resource "aws_cloudwatch_log_group" "mcp_audit_logs" {
  name              = "/aws/ec2/mcp-server/${var.environment}/audit"
  retention_in_days = 90

  tags = {
    Environment = var.environment
    Application = "MCP Server Audit"
    ManagedBy   = "Terraform"
  }
}

# Outputs
output "ec2_public_ip" {
  description = "Public IP address of EC2 instance"
  value       = aws_instance.mcp_server.public_ip
}

output "ec2_instance_id" {
  description = "ID of the EC2 instance"
  value       = aws_instance.mcp_server.id
}

output "mcp_inspector_url" {
  description = "URL for MCP Inspector interface"
  value       = "http://${aws_instance.mcp_server.public_ip}:3000"
}

output "logging_interface_url" {
  description = "URL for centralized logging interface"
  value       = "http://${aws_instance.mcp_server.public_ip}:8080"
}

output "ssh_command" {
  description = "SSH command to connect to EC2 instance"
  value       = "ssh -i ~/.ssh/${var.ec2_key_pair_name}.pem ec2-user@${aws_instance.mcp_server.public_ip}"
}

output "security_group_id" {
  description = "ID of the MCP server security group"
  value       = aws_security_group.mcp_server_sg.id
}
