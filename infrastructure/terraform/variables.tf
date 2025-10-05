# Infrastructure Variables for PostgreSQL MCP Server

variable "aws_region" {
  description = "AWS region for deployment"
  type        = string
  default     = "us-west-2"
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  default     = "dev"
}

# Existing Network Configuration
variable "vpc_id" {
  description = "ID of existing VPC"
  type        = string
}

variable "public_subnet_id" {
  description = "ID of existing public subnet for EC2 instance"
  type        = string
}

variable "private_subnet_ids" {
  description = "List of existing private subnet IDs for RDS"
  type        = list(string)
}

# Security Configuration
variable "allowed_ssh_cidrs" {
  description = "CIDR blocks allowed for SSH access"
  type        = list(string)
  default     = ["10.0.0.0/8"]
}

variable "allowed_web_cidrs" {
  description = "CIDR blocks allowed for web interface access"
  type        = list(string)
  default     = ["10.0.0.0/8"]
}

# EC2 Configuration
variable "ec2_instance_type" {
  description = "EC2 instance type for MCP server"
  type        = string
  default     = "t3.medium"
}

variable "ec2_key_pair_name" {
  description = "Name of existing EC2 key pair for SSH access"
  type        = string
}

# RDS Configuration
variable "rds_instance_class" {
  description = "RDS instance class"
  type        = string
  default     = "db.t3.micro"
}

variable "rds_allocated_storage" {
  description = "Initial storage allocation for RDS (GB)"
  type        = number
  default     = 20
}

variable "rds_max_allocated_storage" {
  description = "Maximum storage allocation for RDS autoscaling (GB)"
  type        = number
  default     = 100
}

variable "db_name" {
  description = "Name of the PostgreSQL database"
  type        = string
  default     = "mcpserver"
}

variable "db_master_username" {
  description = "Master username for PostgreSQL"
  type        = string
  default     = "postgres"
}

variable "db_master_password" {
  description = "Master password for PostgreSQL"
  type        = string
  sensitive   = true
}

variable "db_iam_username" {
  description = "IAM database username for MCP server"
  type        = string
  default     = "mcp_server"
}

# Application Configuration
variable "github_repo_url" {
  description = "GitHub repository URL for MCP server code"
  type        = string
  default     = "https://github.com/your-org/postgresql-mcp.git"
}

variable "domain_name" {
  description = "Domain name for web interfaces (optional)"
  type        = string
  default     = ""
}

variable "enable_deletion_protection" {
  description = "Enable deletion protection for RDS instance"
  type        = bool
  default     = true
}