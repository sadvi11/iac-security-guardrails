# Encryption at rest, backups, and nothing publicly reachable.
package main

resources[r] {
	r := input.planned_values.root_module.resources[_]
}

deny[msg] {
	r := resources[_]
	r.type == "aws_db_instance"
	r.values.storage_encrypted == false
	msg := sprintf("ENCRYPTION: %s has storage_encrypted = false", [r.address])
}

deny[msg] {
	r := resources[_]
	r.type == "aws_db_instance"
	r.values.publicly_accessible == true
	msg := sprintf("EXPOSURE: %s is publicly accessible - move it to a private subnet", [r.address])
}

deny[msg] {
	r := resources[_]
	r.type == "aws_db_instance"
	r.values.backup_retention_period == 0
	msg := sprintf("RESILIENCE: %s has backups disabled (retention 0)", [r.address])
}

deny[msg] {
	r := resources[_]
	r.type == "aws_s3_bucket_acl"
	startswith(r.values.acl, "public")
	msg := sprintf("EXPOSURE: %s sets a public ACL (%s)", [r.address, r.values.acl])
}
