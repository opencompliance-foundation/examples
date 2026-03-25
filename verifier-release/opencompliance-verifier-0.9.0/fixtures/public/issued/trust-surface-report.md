# ExampleCo Issued Trust-Surface Report

**Bundle:** `exampleco-issued-bundle-2026-03-24`  
**Profile:** `issued_narrow_corridor`

## Executive Summary

This synthetic example shows a wider OpenCompliance corridor without pretending the corridor is complete:

- `9` proved claims
- `5` attested claims
- `0` failed claims
- `0` stale-evidence claims
- `0` judgment-required claims
- `0` evidence-missing claims

## Proved

- Administrative identities require MFA in the scoped production environment.
- Infrastructure access in the scoped production environment requires unique named identities with no shared administrative accounts.
- Scoped customer and environment boundaries are enforced with no undeclared cross-environment paths in the production slice.
- Scoped password-quality controls enforce strong minimum length, no maximum-length restriction, and common-password blocking.
- A managed web application firewall is attached to the scoped public ingress path, runs in blocking mode, and has a managed rule set active.
- Audit logging is enabled for the scoped production stack.
- Scoped runtime telemetry is forwarded to the declared central monitoring sink with detection rules enabled.
- Encryption at rest is enabled for the scoped customer data stores and no unencrypted store is present.
- A typed export of periodic access review evidence is present for the current review window.

## Attested

- Security awareness training completion is documented for the current review window.
- Restore testing has been performed in the declared review window.
- Access review closure and high-risk exception resolution are attested for the current review window.
- The incident response runbook is approved, owned, and current for the declared review window.
- Monitoring review cadence, ownership, and retention operations are attested for the scoped production telemetry program.

## Failed


## Stale Evidence


## Judgment Required


## Evidence Missing


## Typed Boundary Layer

The current public corridor uses `LegalLean` as its typed boundary vocabulary.

- Dependency package: `legal-lean`
- Live typed modules:
- `OpenCompliance.Controls.Typed.TypedIdentity` covers `FormalisationBoundary.formal`, `FormalisationBoundary.boundary`, `RequiresHumanDetermination`
- `OpenCompliance.Controls.Typed.TypedLogging` covers `FormalisationBoundary.formal`, `FormalisationBoundary.boundary`, `narrow_audit_logging_runtime`
- `OpenCompliance.Controls.Typed.RiskAcceptance` covers `Defeats`, `risk_acceptance_override`
- `OpenCompliance.Controls.Typed.DiscretionaryTerms` covers `Vague`, `judgment_boundary_inventory`
- `OpenCompliance.Controls.Typed.ComplianceSolver` covers `LegalLean.Solver`, `minimal_claim_corpus`, `runtime_claim_decisions`
- `OpenCompliance.Controls.Typed.PublicRuntime` covers `formalDecision`, `documentaryDecision`, `judgmentDecision`, `public_corridor_runtime_claim_decisions`

- Runtime-consumed claims: `14`
- Runtime status:
- typed control results live: `true`
- risk-acceptance defeasibility live: `true`
- discretionary-term typing live: `true`
- full minimal solver agreement proved: `false`
- Python verdict layer replaced: `true`

## Why This Example Exists

It is public-safe and synthetic, and it exists to show the certificate path as cleanly as possible:

- the corridor is intentionally narrow,
- every in-scope claim is either proved or attested,
- there are no missing-evidence blockers in this pack,
- and the bundle stays honest about what remains outside scope.
