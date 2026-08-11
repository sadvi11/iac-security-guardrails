# Encryption at rest, backups, and no publicly reachable databases.
package main

deny[msg] {
	db := input.resource.aws_db_instance[name]
	db.storage_encrypted == false
	msg := sprintf("ENCRYPTION: aws_db_instance.%s has storage_encrypted = false", [name])
}

deny[msg] {
	db := input.resource.aws_db_instance[name]
	db.publicly_accessible == true
	msg := sprintf("EXPOSURE: aws_db_instance.%s is publicly_accessible - put it in a private subnet", [name])
}

deny[msg] {
	db := input.resource.aws_db_instance[name]
	db.backup_retention_period == 0
	msg := sprintf("RESILIENCE: aws_db_instance.%s has backups disabled (retention 0)", [name])
}

deny[msg] {
	acl := input.resource.aws_s3_bucket_acl[name]
	startswith(acl.acl, "public")
	msg := sprintf("EXPOSURE: aws_s3_bucket_acl.%s sets a public ACL (%s)", [name, acl.acl])
}
