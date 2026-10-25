variable "aws_region" {
  type        = string
  description = "AWS region for deployment"
  default     = "us-east-1"
}

variable "project_name" {
  type        = string
  description = "Project identifier"
  default     = "cloud-dfir-orchestrator"
}

variable "environment" {
  type        = string
  description = "Deployment environment"
  default     = "prod"
}

variable "vpc_id" {
  type        = string
  description = "Target VPC ID where quarantined instances reside (optional, will fetch default if empty)"
  default     = ""
}

variable "retention_days" {
  type        = number
  description = "Retention period for immutable evidence"
  default     = 365
}
