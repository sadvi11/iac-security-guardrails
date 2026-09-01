# Security policy

## Reporting a vulnerability

Open a [private security advisory](https://github.com/sadvi11/iac-security-guardrails/security/advisories/new),
or email **sadhvisharma763@gmail.com**. Please do not open a public issue for a
policy that fails to detect what it claims to detect.

## The failure mode this repository is designed around

A policy scanner has one interesting failure: **it stops detecting things and
the build stays green.** Nobody notices, because the signal for "everything is
fine" and the signal for "the scanner is broken" are identical.

So CI runs both directions on every commit:

- `terraform/compliant/` **must pass.** If it fails, a real control regressed.
- `terraform/violations/` **must be rejected.** If it passes, the scanner has
  quietly stopped working.

The insecure fixture is not broken code. It is working Terraform that would
deploy successfully and should not be allowed to.

## Why this matters more than it sounds

This is not hypothetical. One of the Rego rules here previously matched
**nothing at all** while the suite stayed green: Terraform emits `"tags": null`
for an untagged resource, and `not r.values.tags` evaluates to false for `null`
rather than true. The rule ran, found nothing, and reported success.

The fix was the rule. The lesson was the test structure — the tests were
restructured so one dead policy cannot hide behind its neighbours passing.

## What is covered

Twelve custom Rego rules across five policy files:

| File | Rules | Concern |
|---|---|---|
| `data_protection.rego` | 4 | encryption, versioning, public access |
| `network_exposure.rego` | 3 | management ports open to the internet |
| `iam_least_privilege.rego` | 2 | wildcard actions on wildcard resources |
| `required_tags.rego` | 2 | ownership and cost attribution |
| `data_residency.rego` | 1 | Canadian regions, AWS **and** Azure |

Checkov runs alongside these for the well-known controls, and uploads SARIF so
findings appear in the GitHub Security tab.

## What is out of scope

- **Runtime security.** This blocks insecure infrastructure before merge. It
  says nothing about what happens after deployment.
- **Completeness.** Twelve rules is not a compliance programme. It is the set
  that a scanner does not ship with, most notably Canadian data residency.
- **Provider coverage.** AWS is tested. The Azure residency region names are
  included and are not exercised by a fixture.

## A note on the residency rule

`data_residency.rego` covers both AWS (`ca-central-1`) and Azure
(`canadacentral`, `canadaeast`), because the two clouds name their Canadian
regions differently and a policy written for one silently passes everything in
the other. That is the same class of failure as the `null` tags bug: a rule that
runs, matches nothing, and looks fine.
