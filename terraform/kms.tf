resource "aws_kms_key" "forensics_key" {
  description             = "Dedicated Forensics KMS CMK for Evidence Vault & Re-encrypted Snapshots"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Id      = "dfir-forensics-key-policy"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${local.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow Cloud DFIR Services"
        Effect = "Allow"
        Principal = {
          Service = [
            "ec2.amazonaws.com",
            "s3.amazonaws.com",
            "ssm.amazonaws.com",
            "lambda.amazonaws.com"
          ]
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey",
          "kms:CreateGrant"
        ]
        Resource = "*"
      }
    ]
  })

  tags = {
    Name = "${var.project_name}-forensics-cmk"
  }
}

resource "aws_kms_alias" "forensics_key_alias" {
  name          = "alias/dfir-forensics-vault-key"
  target_key_id = aws_kms_key.forensics_key.key_id
}
