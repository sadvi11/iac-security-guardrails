# Management ports must never be reachable from the internet.
#
# Exposed SSH/RDP is consistently among the most-exploited cloud
# misconfigurations. Covers the inline `ingress` block, the newer standalone
# rule resource, AND port ranges that swallow a management port -- a rule
# opening 0-65535 exposes SSH just as surely as one naming port 22, and a
# policy that only string-matches the port number misses it entirely.
package main

management_ports := {
	22: "SSH",
	3389: "RDP",
	3306: "MySQL",
	5432: "PostgreSQL",
	6379: "Redis",
	27017: "MongoDB",
}

open_cidrs := {"0.0.0.0/0", "::/0"}

resources[r] {
	r := input.planned_values.root_module.resources[_]
}

# Inline ingress blocks, exact port match.
deny[msg] {
	r := resources[_]
	r.type == "aws_security_group"
	rule := r.values.ingress[_]
	cidr := rule.cidr_blocks[_]
	open_cidrs[cidr]
	service := management_ports[rule.from_port]
	msg := sprintf("NETWORK EXPOSURE: %s allows %s (port %d) from %s",
		[r.address, service, rule.from_port, cidr])
}

# Inline ingress blocks, port RANGE that contains a management port.
deny[msg] {
	r := resources[_]
	r.type == "aws_security_group"
	rule := r.values.ingress[_]
	cidr := rule.cidr_blocks[_]
	open_cidrs[cidr]
	management_ports[port]
	rule.from_port < port
	rule.to_port >= port
	msg := sprintf("NETWORK EXPOSURE: %s opens range %d-%d from %s, which includes port %d (%s)",
		[r.address, rule.from_port, rule.to_port, cidr, port, management_ports[port]])
}

# Standalone ingress rule resources.
deny[msg] {
	r := resources[_]
	r.type == "aws_vpc_security_group_ingress_rule"
	open_cidrs[r.values.cidr_ipv4]
	service := management_ports[r.values.from_port]
	msg := sprintf("NETWORK EXPOSURE: %s allows %s (port %d) from %s",
		[r.address, service, r.values.from_port, r.values.cidr_ipv4])
}
