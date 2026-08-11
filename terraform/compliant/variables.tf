variable "region" {
  description = "AWS region. Canadian data-residency policy restricts this to ca-central-1."
  type        = string
  default     = "ca-central-1"
}

variable "name_prefix" {
  description = "Prefix applied to every resource name."
  type        = string
  default     = "guardrails-demo"
}

variable "environment" {
  description = "Deployment environment."
  type        = string
  default     = "prod"

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "environment must be one of: dev, staging, prod."
  }
}

variable "owner" {
  description = "Team accountable for these resources."
  type        = string
  default     = "platform-team"
}

variable "cost_center" {
  description = "Cost centre for chargeback. Required by the tagging policy."
  type        = string
  default     = "CC-1042"
}

variable "vpc_id" {
  description = "VPC the security group belongs to."
  type        = string
  default     = "vpc-00000000000000000"
}

variable "vpc_cidr" {
  description = "CIDR allowed to reach the application on 443."
  type        = string
  default     = "10.0.0.0/16"
}

variable "account_id" {
  description = "AWS account ID, used in the KMS key policy principal."
  type        = string
  default     = "000000000000"
}
