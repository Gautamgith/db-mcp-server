# Terraform Outputs

output "ec2_instance_id" {
  description = "ID of the EC2 instance"
  value       = aws_instance.mcp_server.id
}

output "ec2_public_ip" {
  description = "Public IP address of the EC2 instance"
  value       = aws_instance.mcp_server.public_ip
}

output "ec2_public_dns" {
  description = "Public DNS name of the EC2 instance"
  value       = aws_instance.mcp_server.public_dns
}

output "rds_endpoint" {
  description = "RDS instance endpoint"
  value       = aws_db_instance.postgres.endpoint
}

output "rds_port" {
  description = "RDS instance port"
  value       = aws_db_instance.postgres.port
}

output "database_name" {
  description = "Name of the created database"
  value       = aws_db_instance.postgres.db_name
}

output "mcp_inspector_url" {
  description = "URL for MCP Inspector interface"
  value       = "http://${aws_instance.mcp_server.public_ip}:3000"
}

output "logging_interface_url" {
  description = "URL for logging interface"
  value       = "http://${aws_instance.mcp_server.public_ip}:8080"
}

output "security_group_id" {
  description = "ID of the MCP server security group"
  value       = aws_security_group.mcp_server_sg.id
}

output "iam_role_arn" {
  description = "ARN of the IAM role for EC2 instance"
  value       = aws_iam_role.mcp_server_role.arn
}

output "cloudwatch_log_group_name" {
  description = "Name of the CloudWatch log group"
  value       = aws_cloudwatch_log_group.mcp_server_logs.name
}

output "deployment_commands" {
  description = "Commands to connect and deploy"
  value = {
    ssh_command = "ssh -i ~/.ssh/${var.ec2_key_pair_name}.pem ec2-user@${aws_instance.mcp_server.public_ip}"
    scp_command = "scp -i ~/.ssh/${var.ec2_key_pair_name}.pem"
  }
}