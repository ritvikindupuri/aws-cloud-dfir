resource "random_id" "bucket_suffix" {
  byte_length = 4
}

resource "aws_s3_bucket" "evidence_vault" {
  bucket        = "dfir-evidence-vault-${local.account_id}-${random_id.bucket_suffix.hex}"
  force_destroy = false

  object_lock_enabled = true

  tags = {
    Name        = "Cloud-DFIR-Evidence-Vault"
    Compliance  = "RFC-3227-WORM"
  }
}

resource "aws_s3_bucket_versioning" "evidence_vault_versioning" {
  bucket = aws_s3_bucket.evidence_vault.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "evidence_vault_crypto" {
  bucket = aws_s3_bucket.evidence_vault.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.forensics_key.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "evidence_vault_block" {
  bucket = aws_s3_bucket.evidence_vault.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "evidence_vault_policy" {
  bucket = aws_s3_bucket.evidence_vault.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EnforceTLSRequestsOnly"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.evidence_vault.arn,
          "${aws_s3_bucket.evidence_vault.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })
}
