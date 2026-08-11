# A small but realistic stack that satisfies every policy in policies/.
# This is the positive fixture: CI fails if the scanners flag anything here,
# which catches policies that are accidentally impossible to satisfy.

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.region
}

locals {
  # Every policy that checks tags looks for exactly these keys.
  required_tags = {
    Environment = var.environment
    Owner       = var.owner
    CostCenter  = var.cost_center
    DataClass   = "internal"
  }
}

# ---------------------------------------------------------------------------
# S3 — encrypted, private, versioned, access-logged
# ---------------------------------------------------------------------------

resource "aws_s3_bucket" "data" {
  bucket = "${var.name_prefix}-data"
  tags   = local.required_tags
}

# Access logs go to a separate bucket. Same-bucket logging is a recursion
# problem, and an attacker who can write to the data bucket should not be able
# to edit the record of what they did.
resource "aws_s3_bucket" "logs" {
  # checkov:skip=CKV_AWS_18:This IS the log bucket; it cannot log to itself.
  # checkov:skip=CKV_AWS_144:Cross-region replication is not warranted for logs at this data class.
  # checkov:skip=CKV2_AWS_62:Event notifications are not needed on a log sink.
  # checkov:skip=CKV2_AWS_61:Lifecycle is defined below in a separate resource.
  bucket = "${var.name_prefix}-logs"
  tags   = local.required_tags
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket                  = aws_s3_bucket.logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.data.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_versioning" "logs" {
  bucket = aws_s3_bucket.logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id
  rule {
    id     = "expire-old-logs"
    status = "Enabled"
    filter {}
    # Unfinished multipart uploads bill as storage indefinitely and are
    # invisible in the console. This is a real, recurring cost leak.
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
    expiration {
      days = 365
    }
    noncurrent_version_expiration {
      noncurrent_days = 90
    }
  }
}

resource "aws_s3_bucket_logging" "data" {
  bucket        = aws_s3_bucket.data.id
  target_bucket = aws_s3_bucket.logs.id
  target_prefix = "s3-access/"
}

# Retention keeps storage cost bounded. Without a lifecycle rule an
# ever-growing bucket is a slow, silent cost leak.
resource "aws_s3_bucket_lifecycle_configuration" "data" {
  bucket = aws_s3_bucket.data.id
  rule {
    id     = "transition-and-expire"
    status = "Enabled"
    filter {}
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
    transition {
      days          = 90
      storage_class = "STANDARD_IA"
    }
    noncurrent_version_expiration {
      noncurrent_days = 180
    }
  }
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
  bucket = aws_s3_bucket.data.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.data.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_versioning" "data" {
  bucket = aws_s3_bucket.data.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_kms_key" "data" {
  description             = "CMK for ${var.name_prefix} data at rest"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  tags                    = local.required_tags

  # An explicit key policy. Without one the key falls back to a default that is
  # broader than most people assume.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EnableRootAccountAdmin"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${var.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "AllowS3ServiceUse"
        Effect    = "Allow"
        Principal = { Service = "s3.amazonaws.com" }
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey",
        ]
        Resource = "*"
      },
    ]
  })
}

# ---------------------------------------------------------------------------
# Network — no management port open to the internet
# ---------------------------------------------------------------------------

resource "aws_security_group" "app" {
  name        = "${var.name_prefix}-app"
  description = "Application tier - HTTPS from the load balancer subnet only"
  vpc_id      = var.vpc_id
  tags        = local.required_tags
}

resource "aws_vpc_security_group_ingress_rule" "https_from_vpc" {
  security_group_id = aws_security_group.app.id
  description       = "HTTPS from inside the VPC only"
  cidr_ipv4         = var.vpc_cidr
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "all_out" {
  security_group_id = aws_security_group.app.id
  description       = "Outbound to anywhere - required for package and API access"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
}

# ---------------------------------------------------------------------------
# IAM — scoped to one bucket, no wildcard actions
# ---------------------------------------------------------------------------

resource "aws_iam_policy" "app_s3_read" {
  name        = "${var.name_prefix}-s3-read"
  description = "Read objects from the data bucket only"
  tags        = local.required_tags

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:ListBucket",
        ]
        Resource = [
          aws_s3_bucket.data.arn,
          "${aws_s3_bucket.data.arn}/*",
        ]
      },
    ]
  })
}
