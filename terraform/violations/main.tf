# DELIBERATELY INSECURE. This is a test fixture, never a deployment target.
#
# Every resource below breaks at least one policy on purpose. CI asserts that
# the scanners FAIL on this directory -- a guardrail that never catches
# anything is indistinguishable from no guardrail, and that failure mode is
# silent. Each violation is numbered against the policy it should trip.

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# V1 - data residency: us-east-1 puts Canadian data outside the country.
provider "aws" {
  region = "us-east-1"

  # These let `terraform plan` run in CI with no real credentials, so policy
  # evaluation never needs cloud access. They affect planning only, not what
  # gets created.
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
}

# V2 - unencrypted, unversioned, public-ACL bucket with no required tags.
resource "aws_s3_bucket" "leaky" {
  bucket = "guardrails-demo-leaky"
  # no tags block at all
}

resource "aws_s3_bucket_acl" "leaky" {
  bucket = aws_s3_bucket.leaky.id
  acl    = "public-read"
}

# V3 - SSH open to the entire internet. The single most exploited
# misconfiguration in cloud breach reports.
resource "aws_security_group" "wide_open" {
  name        = "wide-open"
  description = "Allows SSH and RDP from anywhere"

  ingress {
    description = "SSH from the world"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "RDP from the world"
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# V4 - IAM policy granting every action on every resource.
resource "aws_iam_policy" "god_mode" {
  name = "god-mode"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      },
    ]
  })
}

# V5 - unencrypted database, publicly reachable, no backups.
resource "aws_db_instance" "exposed" {
  identifier                = "guardrails-demo-db"
  engine                    = "postgres"
  instance_class            = "db.t3.micro"
  allocated_storage         = 20
  username                  = "admin"
  publicly_accessible       = true
  storage_encrypted         = false
  backup_retention_period   = 0
  skip_final_snapshot       = true
  final_snapshot_identifier = null
}
