# Management ports must never be open to the internet.
#
# Exposed SSH/RDP is consistently among the most-exploited cloud
# misconfigurations. This policy covers both the inline `ingress` block and the
# newer standalone aws_vpc_security_group_ingress_rule resource, because a rule
# that only understands one of them gives false confidence.
package main

management_ports := {22: "SSH", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB"}

open_cidrs := {"0.0.0.0/0", "::/0"}

# Inline ingress blocks on aws_security_group.
deny[msg] {
	sg := input.resource.aws_security_group[name]
	rule := sg.ingress[_]
	cidr := rule.cidr_blocks[_]
	open_cidrs[cidr]
	port := rule.from_port
	service := management_ports[port]
	msg := sprintf(
		"NETWORK EXPOSURE: aws_security_group.%s allows %s (port %d) from %s",
		[name, service, port, cidr],
	)
}

# Standalone ingress rule resources.
deny[msg] {
	rule := input.resource.aws_vpc_security_group_ingress_rule[name]
	open_cidrs[rule.cidr_ipv4]
	service := management_ports[rule.from_port]
	msg := sprintf(
		"NETWORK EXPOSURE: aws_vpc_security_group_ingress_rule.%s allows %s (port %d) from %s",
		[name, service, rule.from_port, rule.cidr_ipv4],
	)
}

# A rule spanning a port range that swallows a management port, e.g. 0-65535.
deny[msg] {
	sg := input.resource.aws_security_group[name]
	rule := sg.ingress[_]
	cidr := rule.cidr_blocks[_]
	open_cidrs[cidr]
	management_ports[port]
	rule.from_port <= port
	rule.to_port >= port
	rule.from_port != port
	msg := sprintf(
		"NETWORK EXPOSURE: aws_security_group.%s opens range %d-%d from %s, which includes port %d (%s)",
		[name, rule.from_port, rule.to_port, cidr, port, management_ports[port]],
	)
}
