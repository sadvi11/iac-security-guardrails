# IaC Security Guardrails

[![IaC policy checks](https://github.com/sadvi11/iac-security-guardrails/actions/workflows/policy-check.yml/badge.svg)](https://github.com/sadvi11/iac-security-guardrails/actions/workflows/policy-check.yml)
![Checkov](https://img.shields.io/badge/Checkov-3.3-6C4AB6)
![OPA](https://img.shields.io/badge/OPA-Rego-7D9199?logo=openpolicyagent&logoColor=white)
![Terraform](https://img.shields.io/badge/Terraform-1.9-7B42BC?logo=terraform&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)

Policy-as-code that blocks insecure infrastructure before it merges — Checkov
for the well-known controls, and custom **Rego** policies for the rules no
scanner ships with, like Canadian data residency.

**The pipeline tests the guardrails in both directions.** A secure fixture must
pass, and a deliberately insecure one **must be rejected**. That second
direction is the one teams skip, and it is exactly how a scanner quietly stops
detecting anything after a version bump — with a green badge the whole time.

## Both fixtures are valid Terraform

```
terraform/compliant   → terraform validate: Success   checkov: 46 passed, 0 failed
terraform/violations  → terraform validate: Success   checkov: 29 failed
```

Neither is broken code. `terraform/violations` would deploy cleanly and hand you
a public database, an SSH port open to the internet, an unencrypted bucket, and
an IAM policy granting `*` on `*`. Terraform has no opinion about any of that.
**Policy is the only thing that separates them**, which is the entire argument
for this repository.

## What the custom policies catch that Checkov does not

Checkov is excellent at rules that are universally true. It cannot know your
organisation's rules. These are written in Rego and live in [`policies/`](policies/):

| Policy | Rule | Why it is not in a scanner |
|---|---|---|
| `data_residency` | Resources must be in `ca-central-1`, `ca-west-1`, `canadacentral` or `canadaeast` | Only your contracts know where data is legally allowed to live |
| `required_tags` | `Environment`, `Owner`, `CostCenter` on every taggable resource | Tag keys are organisation-specific; untagged resources make chargeback impossible |
| `network_exposure` | No management port reachable from `0.0.0.0/0` — including **port ranges that swallow one** | Covers both inline `ingress` and the newer standalone rule resource |
| `iam_least_privilege` | No `Action: "*"`, and never `*` on `*` | Parses the embedded JSON policy document, not just the resource |
| `data_protection` | Encryption at rest, backups enabled, no public database or bucket ACL | |

The range check matters: a rule opening `0-65535` exposes SSH just as surely as
one naming port 22, and a policy that only string-matches the port number misses
it entirely.

### Why these run against a plan, not raw HCL

The first version parsed `.tf` files directly and immediately failed on its own
compliant fixture:

```
DATA RESIDENCY: provider region "${var.region}" is outside Canada
```

Static HCL parsing cannot resolve a variable. It sees the literal string
`${var.region}` and has no idea whether that becomes `ca-central-1` or
`us-east-1` — which makes it useless for precisely the check being made. Tags
composed from `locals` or `merge()` have the same problem.

So the pipeline runs `terraform plan` and evaluates the resulting JSON, where
every variable, local and interpolation is already resolved. The provider blocks
set `skip_credentials_validation`, so **planning needs no real AWS account** —
policy evaluation never touches a cloud API and there is no credential in CI to
leak.

## The interesting part: tuning is the actual skill

Running a scanner is one command. **Deciding which findings to enforce is the
job.** Checkov flagged six issues on the first version of the "compliant"
fixture. That triage is recorded rather than hidden:

- **Fixed** (they were right) — S3 access logging to a separate bucket, an
  explicit KMS key policy, lifecycle rules, and aborting incomplete multipart
  uploads, which bill as storage indefinitely and are invisible in the console.
- **Skipped with a written reason** in [`.checkov.yaml`](.checkov.yaml) — three
  rules that genuinely do not apply, each with the condition that would make us
  revisit it.

A scanner tuned by deleting findings is worse than no scanner, because it looks
clean. Every skip here states why, and what would change our mind.

## What CI enforces

| Check | `compliant/` | `violations/` |
|---|---|---|
| `terraform fmt` / `validate` | must pass | must pass (it is valid, just dangerous) |
| Checkov | **0 findings** | **≥ 15 findings**, non-zero exit |
| Custom Rego policies | all satisfied | **every policy family must fire** |

That last cell is deliberate, and it has already paid for itself. The build
asserts each of the seven policy families appears in the output — and that check
caught a **dead policy**: the tagging rule matched nothing, because a resource
with no tags appears in a plan as `"tags": null` rather than an absent key, and
`not r.values.tags` does not match a defined null. Three untagged resources
sailed through while the suite reported success. Without the negative fixture
and the per-family assertion, that policy would have shipped looking healthy.

Findings are uploaded as SARIF, so they appear in the repository's **Security**
tab rather than only in build logs.

## Run it locally

```bash
make install     # checkov + conftest into a local venv
make check       # both directions, exactly what CI runs
make compliant   # scan the good fixture
make violations  # scan the bad fixture and see what gets caught
make fmt         # terraform fmt -recursive
```

Costs nothing. `terraform plan` runs with dummy credentials and
`skip_credentials_validation`, so no AWS account, no state file, and no
credential is involved anywhere.

## Repository layout

```
.
├── policies/                 # custom Rego policies
├── terraform/
│   ├── compliant/            # positive fixture — must pass
│   └── violations/           # negative fixture — must be caught
├── .checkov.yaml             # justified exceptions, the audit trail
├── .pre-commit-config.yaml   # same checks before the commit lands
└── .github/workflows/        # both directions enforced
```

## Using this on a real repository

```bash
checkov -d path/to/your/terraform --config-file .checkov.yaml

terraform -chdir=path/to/your/terraform plan -out=tf.plan
terraform -chdir=path/to/your/terraform show -json tf.plan > plan.json
conftest test --policy policies plan.json
```

The policies are not specific to the fixtures — point them at any Terraform.

## Author

Sadhvi Sharma · Cloud & AI Engineer · Calgary, Alberta
[github.com/sadvi11](https://github.com/sadvi11)
