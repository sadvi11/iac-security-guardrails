# No wildcard IAM.
#
# Action "*" on Resource "*" is administrator access by another name. It is
# usually written as a temporary unblock and then never narrowed. This parses
# the embedded JSON policy document rather than pattern-matching the HCL.
package main

resources[r] {
	r := input.planned_values.root_module.resources[_]
}

statements[[r, s]] {
	r := resources[_]
	r.type == "aws_iam_policy"
	doc := json.unmarshal(r.values.policy)
	s := doc.Statement[_]
	s.Effect == "Allow"
}

deny[msg] {
	[r, s] := statements[_]
	wildcard(s.Action)
	wildcard(s.Resource)
	msg := sprintf("IAM: %s allows \"*\" on \"*\" - this is administrator access", [r.address])
}

deny[msg] {
	[r, s] := statements[_]
	wildcard(s.Action)
	not wildcard(s.Resource)
	msg := sprintf("IAM: %s allows action \"*\" - grant only the actions actually used", [r.address])
}

wildcard(v) {
	v == "*"
}

wildcard(v) {
	is_array(v)
	v[_] == "*"
}
