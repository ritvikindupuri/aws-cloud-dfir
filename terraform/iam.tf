# --- Step Functions IAM Role ---
resource "aws_iam_role" "step_functions_role" {
  name = "${var.project_name}-sfn-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "states.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "step_functions_policy" {
  name = "${var.project_name}-sfn-policy"
  role = aws_iam_role.step_functions_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "lambda:InvokeFunction"
        ]
        Resource = "*"
      }
    ]
  })
}

# --- Lambda Execution IAM Role ---
resource "aws_iam_role" "lambda_role" {
  name = "${var.project_name}-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "lambda_dfir_policy" {
  name = "${var.project_name}-lambda-policy"
  role = aws_iam_role.lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EC2ForensicActions"
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:ModifyInstanceAttribute",
          "ec2:CreateTags",
          "ec2:CreateSnapshot",
          "ec2:DescribeSnapshots",
          "ec2:CopySnapshot"
        ]
        Resource = "*"
      },
      {
        Sid    = "SSMActions"
        Effect = "Allow"
        Action = [
          "ssm:SendCommand",
          "ssm:GetCommandInvocation",
          "ssm:ListCommands",
          "ssm:DescribeDocument"
        ]
        Resource = "*"
      },
      {
        Sid    = "KMSAccess"
        Effect = "Allow"
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey",
          "kms:CreateGrant"
        ]
        Resource = [aws_kms_key.forensics_key.arn]
      },
      {
        Sid    = "EvidenceS3VaultAccess"
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject",
          "s3:ListBucket",
          "s3:PutObjectLegalHold"
        ]
        Resource = [
          aws_s3_bucket.evidence_vault.arn,
          "${aws_s3_bucket.evidence_vault.arn}/*"
        ]
      },
      {
        Sid    = "CloudWatchLogging"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:*"
      }
    ]
  })
}

# --- Instance Profile for Monitored Hosts (SSM & S3 Evidence Streaming) ---
resource "aws_iam_role" "monitored_ec2_ssm_role" {
  name = "${var.project_name}-target-ec2-role"

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
}

resource "aws_iam_role_policy_attachment" "ec2_ssm_core" {
  role       = aws_iam_role.monitored_ec2_ssm_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy" "ec2_evidence_upload" {
  name = "AllowEvidenceVaultUpload"
  role = aws_iam_role.monitored_ec2_ssm_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:AbortMultipartUpload"
        ]
        Resource = [
          "${aws_s3_bucket.evidence_vault.arn}/evidence/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = [aws_kms_key.forensics_key.arn]
      }
    ]
  })
}

resource "aws_iam_instance_profile" "monitored_ec2_profile" {
  name = "${var.project_name}-target-ec2-profile"
  role = aws_iam_role.monitored_ec2_ssm_role.name
}
