# ADR 002: Use Checkov for general controls and Rego for organisation-specific rules

- Status: Accepted
- Applies to: `.checkov.yaml`, `policies/`, the `checkov` and `conftest` jobs

## Context

Two kinds of rule are needed. Some are true for almost everyone (S3 encryption,
no public database). Others only exist because of one organisation's contracts
and conventions (data must stay in Canada, tags must include `CostCenter`).

## Options considered

| Option | Pros | Cons |
|---|---|---|
| A. Checkov only | Large built-in rule library, little to maintain | Cannot express organisation-specific rules without writing custom checks in its own format |
| B. Rego/conftest only | One policy language, full control | Re-implements hundreds of well-known checks and the maintenance that comes with them |
| C. Both, with a clear split | Built-in library for common controls, Rego for local rules | Two tools, two sets of output to read |

## Decision

Option C. Checkov enforces the common controls; Rego covers the rules no
scanner ships. Every Checkov skip in `.checkov.yaml` carries a written reason and
the condition that would make us revisit it.

Both are tested in both directions: the compliant fixture must produce zero
findings, and the violations fixture must be rejected. For Rego, CI also asserts
that each policy family appears in the failure output, so one live policy cannot
hide a dead one.

## Consequences

- Two outputs to read in CI, mitigated by the job summary and the SARIF upload
  of Checkov results to the Security tab.
- The Checkov version is pinned (`checkov==3.3.10`) so a new release cannot
  change results silently; upgrading is a deliberate change that the
  violations-fixture threshold (at least 15 findings) will check.
- The per-family assertion is a text match on the policy message prefix. A
  family whose message prefix is renamed will fail CI until the workflow is
  updated, which is the intended loud failure.
- Rego rules have no unit tests of their own yet; they are tested only through
  the two fixtures (see "What I would change for production" in the README).
