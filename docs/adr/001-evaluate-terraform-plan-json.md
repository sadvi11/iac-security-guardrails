# ADR 001: Evaluate policies against the Terraform plan JSON, not raw HCL

- Status: Accepted
- Applies to: `policies/*.rego`, the `conftest` job in `.github/workflows/policy-check.yml`

## Context

The custom Rego policies (data residency, required tags, network exposure, IAM,
data protection) need to read resource attributes such as the provider region,
tags and security group rules.

The first version of this repo parsed the `.tf` files directly. It failed on its
own compliant fixture: the provider region was the unresolved string
`${var.region}`, so the residency rule could not tell `ca-central-1` from
`us-east-1`. Tags built from `locals` or `merge()` have the same problem.

## Options considered

| Option | Pros | Cons |
|---|---|---|
| A. Parse raw HCL (conftest can read `.tf`) | No `terraform` binary needed; fast | Variables, locals and functions are not resolved, so any rule that depends on a computed value is wrong or blind |
| B. Evaluate `terraform show -json` of a plan | Variables, locals and interpolations are already resolved; one stable JSON shape | Needs `terraform init` and `plan` in CI; values only known after apply are not visible |
| C. Evaluate state after apply | Sees real values | Too late: the resource already exists. Needs real credentials |

## Decision

Option B. CI runs `terraform init -backend=false` and `terraform plan` for each
fixture, converts the plan with `terraform show -json`, and runs
`conftest test --policy policies` on the result.

The provider blocks set `skip_credentials_validation`,
`skip_requesting_account_id` and `skip_metadata_api_check`, and CI exports dummy
credentials, so planning never calls AWS and no real credential exists in the
pipeline.

## Consequences

- Policies see resolved values, so the residency rule works with
  `region = var.region`.
- A plan represents "null" explicitly. A resource with no tags appears as
  `"tags": null`, not as a missing key, and in Rego `null` is a defined value.
  This is the cause of the dead tagging rule recorded in the README.
- Attributes that Terraform cannot know until apply are absent from
  `planned_values` (the JSON format reports them under `after_unknown`). A
  policy that depends on such an attribute can pass when it should not. Policies
  should be written so that missing data is treated deliberately, and new ones
  should be exercised against the violations fixture.
- CI needs the Terraform CLI and provider download (network access to the
  Terraform registry), but no cloud credentials.

## References

- Terraform JSON output format: https://developer.hashicorp.com/terraform/internals/json-format
- `terraform show`: https://developer.hashicorp.com/terraform/cli/commands/show
- Conftest: https://www.conftest.dev/
