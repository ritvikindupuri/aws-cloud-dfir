# --- Lambda 1: Trigger Triage ---
data "archive_file" "trigger_triage_zip" {
  type        = "zip"
  source_file = "${path.module}/lambdas/trigger_triage/index.py"
  output_path = "${path.module}/lambdas/trigger_triage.zip"
}

resource "aws_lambda_function" "trigger_triage" {
  filename         = data.archive_file.trigger_triage_zip.output_path
  function_name    = "${var.project_name}-trigger-triage"
  role             = aws_iam_role.lambda_role.arn
  handler          = "index.handler"
  source_code_hash = data.archive_file.trigger_triage_zip.output_base64sha256
  runtime          = "python3.11"
  timeout          = 60

  environment {
    variables = {
      EVIDENCE_BUCKET   = aws_s3_bucket.evidence_vault.id
      KMS_KEY_ID        = aws_kms_key.forensics_key.arn
      SSM_DOCUMENT_NAME = aws_ssm_document.live_volatile_acquisition.name
    }
  }
}

# --- Lambda 2: Isolate Instance ---
data "archive_file" "isolate_instance_zip" {
  type        = "zip"
  source_file = "${path.module}/lambdas/isolate_instance/index.py"
  output_path = "${path.module}/lambdas/isolate_instance.zip"
}

resource "aws_lambda_function" "isolate_instance" {
  filename         = data.archive_file.isolate_instance_zip.output_path
  function_name    = "${var.project_name}-isolate-instance"
  role             = aws_iam_role.lambda_role.arn
  handler          = "index.handler"
  source_code_hash = data.archive_file.isolate_instance_zip.output_base64sha256
  runtime          = "python3.11"
  timeout          = 60

  environment {
    variables = {
      QUARANTINE_SG_ID = aws_security_group.quarantine_sg.id
    }
  }
}

# --- Lambda 3: Snapshot EBS ---
data "archive_file" "snapshot_ebs_zip" {
  type        = "zip"
  source_file = "${path.module}/lambdas/snapshot_ebs/index.py"
  output_path = "${path.module}/lambdas/snapshot_ebs.zip"
}

resource "aws_lambda_function" "snapshot_ebs" {
  filename         = data.archive_file.snapshot_ebs_zip.output_path
  function_name    = "${var.project_name}-snapshot-ebs"
  role             = aws_iam_role.lambda_role.arn
  handler          = "index.handler"
  source_code_hash = data.archive_file.snapshot_ebs_zip.output_base64sha256
  runtime          = "python3.11"
  timeout          = 180
}

# --- Lambda 4: Re-encrypt Evidence ---
data "archive_file" "reencrypt_evidence_zip" {
  type        = "zip"
  source_file = "${path.module}/lambdas/reencrypt_evidence/index.py"
  output_path = "${path.module}/lambdas/reencrypt_evidence.zip"
}

resource "aws_lambda_function" "reencrypt_evidence" {
  filename         = data.archive_file.reencrypt_evidence_zip.output_path
  function_name    = "${var.project_name}-reencrypt-evidence"
  role             = aws_iam_role.lambda_role.arn
  handler          = "index.handler"
  source_code_hash = data.archive_file.reencrypt_evidence_zip.output_base64sha256
  runtime          = "python3.11"
  timeout          = 300

  environment {
    variables = {
      FORENSICS_KMS_KEY_ARN = aws_kms_key.forensics_key.arn
      EVIDENCE_BUCKET       = aws_s3_bucket.evidence_vault.id
    }
  }
}

# --- Lambda 5: Run Volatility Analyzer ---
data "archive_file" "run_volatility_zip" {
  type        = "zip"
  source_file = "${path.module}/lambdas/run_volatility/index.py"
  output_path = "${path.module}/lambdas/run_volatility.zip"
}

resource "aws_lambda_function" "run_volatility" {
  filename         = data.archive_file.run_volatility_zip.output_path
  function_name    = "${var.project_name}-run-volatility"
  role             = aws_iam_role.lambda_role.arn
  handler          = "index.handler"
  source_code_hash = data.archive_file.run_volatility_zip.output_base64sha256
  runtime          = "python3.11"
  timeout          = 180

  environment {
    variables = {
      EVIDENCE_BUCKET   = aws_s3_bucket.evidence_vault.id
      ECS_CLUSTER       = ""
      TASK_DEFINITION   = ""
      SUBNET_ID         = ""
      SECURITY_GROUP_ID = aws_security_group.quarantine_sg.id
    }
  }
}
