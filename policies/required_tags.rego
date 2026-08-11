# Mandatory tagging.
#
# Untagged resources cause the "whose is this and can we delete it?" thread,
# and make chargeback impossible. Enforcing in CI is far cheaper than
# reconciling a bill afterwards.
#
# Plan-based, so tags composed from locals or merge() are seen as their final
# resolved value rather than an unreadable expression.
package main

required_tags := {"Environment", "Owner", "CostCenter"}

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

resources[r] {
	r := input.planned_values.root_module.resources[_]
}

# A resource with no tags block appears in the plan as "tags": null, NOT as an
# absent key. `not r.values.tags` therefore does not match, because null is a
# defined value in Rego. object.get with a null default covers both shapes.
#
# This exact bug made the rule silently dead: it matched nothing while the
# build stayed green. The negative fixture is what surfaced it, which is the
# whole argument for testing policies in both directions.
deny[msg] {
	r := resources[_]
	taggable_types[r.type]
	is_null(object.get(r.values, "tags", null))
	msg := sprintf("TAGGING: %s has no tags. Required: %s",
		[r.address, concat(", ", sort([t | required_tags[t]]))])
}

deny[msg] {
	r := resources[_]
	taggable_types[r.type]
	tags := r.values.tags
	is_object(tags)
	required_tags[required]
	not tags[required]
	msg := sprintf("TAGGING: %s is missing required tag %q", [r.address, required])
}
