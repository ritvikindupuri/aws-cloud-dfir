output "evidence_vault_bucket" {
  description = "Name of the S3 Evidence Vault Bucket (WORM Object Lock)"
  value       = aws_s3_bucket.evidence_vault.id
}

output "forensics_kms_key_arn" {
  description = "ARN of the Forensics KMS Customer Managed Key"
  value       = aws_kms_key.forensics_key.arn
}

output "quarantine_security_group_id" {
  description = "Security Group ID used for Zero-Trust Instance Isolation"
  value       = aws_security_group.quarantine_sg.id
}

output "step_function_state_machine_arn" {
  description = "ARN of the Cloud DFIR Step Functions State Machine"
  value       = aws_sfn_state_machine.cloud_dfir_pipeline.arn
}

output "ssm_document_name" {
  description = "Name of the SSM Live Volatile Acquisition Document"
  value       = aws_ssm_document.live_volatile_acquisition.name
}

output "monitored_ec2_instance_profile" {
  description = "Instance profile name to attach to EC2 instances for SSM & S3 streaming"
  value       = aws_iam_instance_profile.monitored_ec2_profile.name
}
