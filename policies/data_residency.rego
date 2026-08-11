# Canadian data residency.
#
# Banks, insurers and government in Canada frequently contract that personal
# data stays in-country. This is the policy most likely to be organisation-
# specific rather than shipped by a scanner -- Checkov has no idea where your
# data is legally allowed to live.
package main

allowed_regions := {
	"ca-central-1",  # AWS Canada (Central)
	"ca-west-1",     # AWS Canada West (Calgary)
	"canadacentral", # Azure
	"canadaeast",    # Azure
}

deny[msg] {
	region := input.provider.aws.region
	is_string(region)
	not allowed_regions[region]
	msg := sprintf(
		"DATA RESIDENCY: provider region %q is outside Canada. Allowed: %v",
		[region, concat(", ", sort([r | allowed_regions[r]]))],
	)
}

# Catch a region pinned directly on a resource, which bypasses the provider.
deny[msg] {
	resource := input.resource[type][name]
	region := resource.region
	is_string(region)
	not allowed_regions[region]
	msg := sprintf(
		"DATA RESIDENCY: %s.%s pins region %q, outside Canada",
		[type, name, region],
	)
}
