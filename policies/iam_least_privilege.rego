# No wildcard IAM.
#
# Action "*" on Resource "*" is administrator access by another name. It is
# usually written as a temporary unblock and then never narrowed.
package main

deny[msg] {
	policy := input.resource.aws_iam_policy[name]
	doc := json.unmarshal(policy.policy)
	statement := doc.Statement[_]
	statement.Effect == "Allow"
	wildcard_action(statement.Action)
	msg := sprintf("IAM: aws_iam_policy.%s allows action \"*\" - grant only the actions actually used", [name])
}

deny[msg] {
	policy := input.resource.aws_iam_policy[name]
	doc := json.unmarshal(policy.policy)
	statement := doc.Statement[_]
	statement.Effect == "Allow"
	wildcard_resource(statement.Resource)
	wildcard_action(statement.Action)
	msg := sprintf("IAM: aws_iam_policy.%s allows \"*\" on \"*\" - this is admin access", [name])
}

wildcard_action(action) {
	action == "*"
}

wildcard_action(action) {
	action[_] == "*"
}

wildcard_resource(resource) {
	resource == "*"
}

wildcard_resource(resource) {
	resource[_] == "*"
}
