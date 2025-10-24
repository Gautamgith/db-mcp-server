# RDS Module Outputs

output "rds_endpoint" {
  description = "RDS instance endpoint (host:port)"
  value       = aws_db_instance.postgres.endpoint
}

output "rds_address" {
  description = "RDS instance address (host only)"
  value       = aws_db_instance.postgres.address
}

output "rds_port" {
  description = "RDS instance port"
  value       = aws_db_instance.postgres.port
}

output "rds_instance_id" {
  description = "RDS instance identifier"
  value       = aws_db_instance.postgres.id
}

output "rds_resource_id" {
  description = "RDS instance resource ID for IAM policies"
  value       = aws_db_instance.postgres.resource_id
}

output "rds_arn" {
  description = "ARN of the RDS instance"
  value       = aws_db_instance.postgres.arn
}

output "rds_security_group_id" {
  description = "ID of the RDS security group"
  value       = aws_security_group.rds_sg.id
}

output "database_name" {
  description = "Name of the default database"
  value       = aws_db_instance.postgres.db_name
}

output "master_username" {
  description = "Master username for the database"
  value       = aws_db_instance.postgres.username
  sensitive   = true
}

output "monitoring_role_arn" {
  description = "ARN of the RDS monitoring role"
  value       = aws_iam_role.rds_monitoring_role.arn
}

output "iam_auth_enabled" {
  description = "Whether IAM authentication is enabled"
  value       = aws_db_instance.postgres.iam_database_authentication_enabled
}
