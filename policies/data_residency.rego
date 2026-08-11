# Canadian data residency.
#
# Banks, insurers and government in Canada frequently contract that personal
# data stays in-country. No scanner ships this rule -- Checkov cannot know
# where your data is legally allowed to live.
#
# Evaluated against a Terraform PLAN, not raw HCL. Static HCL parsing sees
# "${var.region}" and cannot tell you whether that resolves to ca-central-1 or
# us-east-1, which makes it useless for exactly this check.
package main

allowed_regions := {
	"ca-central-1",  # AWS Canada (Central)
	"ca-west-1",     # AWS Canada West (Calgary)
	"canadacentral", # Azure
	"canadaeast",    # Azure
}

# A literal region on the provider.
provider_region := r {
	r := input.configuration.provider_config.aws.expressions.region.constant_value
}

# A region supplied by a variable -- resolved from the plan's variable values.
provider_region := r {
	ref := input.configuration.provider_config.aws.expressions.region.references[_]
	startswith(ref, "var.")
	name := substring(ref, 4, -1)
	r := input.variables[name].value
}

deny[msg] {
	region := provider_region
	not allowed_regions[region]
	msg := sprintf(
		"DATA RESIDENCY: provider region %q is outside Canada. Allowed: %s",
		[region, concat(", ", sort([r | allowed_regions[r]]))],
	)
}
