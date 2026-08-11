# Mandatory tagging.
#
# Untagged resources are the root cause of every "whose is this and can we
# delete it?" thread, and they make chargeback impossible. Enforcing tags in CI
# is far cheaper than reconciling a bill afterwards.
package main

required_tags := {"Environment", "Owner", "CostCenter"}

# Resource types that support tags and are worth governing. Deliberately a
# denylist of untaggable types would be fragile, so this is an allowlist.
taggable_types := {
	"aws_s3_bucket",
	"aws_security_group",
	"aws_iam_policy",
	"aws_kms_key",
	"aws_db_instance",
	"aws_instance",
	"aws_lambda_function",
	"aws_ecs_service",
}

deny[msg] {
	taggable_types[type]
	resource := input.resource[type][name]
	not resource.tags
	msg := sprintf("TAGGING: %s.%s has no tags block. Required: %v",
		[type, name, concat(", ", sort([t | required_tags[t]]))])
}

deny[msg] {
	taggable_types[type]
	resource := input.resource[type][name]
	tags := resource.tags
	is_object(tags)
	required_tags[required]
	not tags[required]
	msg := sprintf("TAGGING: %s.%s is missing required tag %q", [type, name, required])
}
