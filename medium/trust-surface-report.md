# ExampleCo Medium Trust-Surface Report

**Bundle:** `exampleco-medium-bundle-2026-03-24`  
**Profile:** `medium_multiframework_corridor`

## Executive Summary

This synthetic example shows a wider OpenCompliance corridor without pretending the corridor is complete:

- `17` proved claims
- `12` attested claims
- `0` failed claims
- `0` stale-evidence claims
- `3` judgment-required claims
- `1` evidence-missing claim

## Proved

- Administrative identities require MFA and conditional access in the scoped production environment.
- Infrastructure access in the scoped production environment requires unique named identities with no shared administrative accounts.
- Scoped customer and environment boundaries are enforced with no undeclared cross-environment paths in the production slice.
- Scoped password-quality controls enforce strong minimum length, no maximum-length restriction, and common-password blocking.
- A managed web application firewall is attached to the scoped public ingress path, runs in blocking mode, and has a managed rule set active.
- Audit logging is enabled with a declared retention window for the scoped production runtime.
- Scoped runtime telemetry is forwarded to the declared central monitoring sink with detection rules enabled.
- Public ingress is HTTPS-only with managed certificates and TLS 1.2 or higher.
- The managed network boundary is attached to the declared ingress path for scoped public services.
- Administrative ingress is restricted to approved source ranges at the managed network boundary.
- Plaintext transport is disabled on the scoped public ingress path.
- Encryption at rest is enabled for the scoped customer data stores and no unencrypted store is present.
- Scoped runtime service accounts do not use user-managed long-lived keys.
- The scoped workload runs only in the declared approved regions.
- Backup snapshots are scheduled with a declared immutable retention window.
- Default branch protections are enforced for the scoped production repository.
- CI workflow policy constrains deployment to reviewed workflows and protected refs.

## Attested

- Security awareness completion is documented for the current review period.
- A restore exercise is documented inside the declared review window.
- The processor register is current and DPA coverage is declared for the reviewed subprocessors.
- The DSR runbook is approved and has a named owner for the current review window.
- The production change-review policy is approved and declares an emergency change path for the current review window.
- Access review closure and high-risk exception resolution are attested for the current review window.
- Monitoring review cadence, ownership, and retention operations are attested for the scoped production telemetry program.
- Configuration exceptions are current, owned, and not already expired in the current review window.
- Patch exceptions declare compensating controls and no declared exception is already expired in the current review window.
- The incident response runbook is approved, owned, and current for the declared review window.
- Incident escalation contacts and notification paths are current for the declared review window.
- High-risk vendor agreements carry the required security and privacy terms for the current review window.

## Failed


## Stale Evidence


## Judgment Required

- Privacy-by-design adequacy has been demonstrated for the full product change process.
- Patch cadence and exception thresholds are adequate for the in-scope production assets.
- Vendor tiering, review cadence, and inherited-control allocation are adequate for the in-scope dependency set.

## Evidence Missing

- A typed export of periodic access review evidence is present for the current review window.

## Typed Boundary Layer

The current public corridor uses `LegalLean` as its typed boundary vocabulary.

- Dependency package: `legal-lean`
- Live typed modules:
- `OpenCompliance.Controls.Typed.TypedIdentity` covers `FormalisationBoundary.formal`, `FormalisationBoundary.boundary`, `RequiresHumanDetermination`
- `OpenCompliance.Controls.Typed.TypedLogging` covers `FormalisationBoundary.formal`, `FormalisationBoundary.boundary`, `narrow_audit_logging_runtime`
- `OpenCompliance.Controls.Typed.RiskAcceptance` covers `Defeats`, `risk_acceptance_override`
- `OpenCompliance.Controls.Typed.DiscretionaryTerms` covers `Vague`, `judgment_boundary_inventory`
- `OpenCompliance.Controls.Typed.ComplianceSolver` covers `LegalLean.Solver`, `minimal_claim_corpus`, `runtime_claim_decisions`

- Runtime-consumed claims: `0`
- Runtime status:
- typed control results live: `true`
- risk-acceptance defeasibility live: `true`
- discretionary-term typing live: `true`
- full minimal solver agreement proved: `false`
- Python verdict layer replaced: `false`

## Why This Example Exists

It is public-safe and synthetic, but it demonstrates a more serious corridor than the minimal pack:

- multi-framework family mappings,
- explicit control references back into the synthetic OpenCompliance catalog,
- a cleaner split between runtime proofs and signed attestations,
- a deeper ISO 27001 and SOC 2 overlap slice for perimeter, centralized monitoring, ingress-boundary, and transport controls,
- a first public mixed-control decomposition for change management,
- and a still-honest boundary where legal or adequacy judgment remains human.
