# ExampleCo Minimal Trust-Surface Report

**Bundle:** `exampleco-minimal-bundle-2026-03-24`  
**Profile:** `minimal_saas_corridor`

## Executive Summary

This synthetic example shows the intended OpenCompliance split:

- `2` proved claims
- `1` attested claim
- `0` failed claims
- `0` stale-evidence claims
- `1` judgment-required claim
- `1` evidence-missing claim

## Proved

- Administrative identities require MFA in the scoped production environment.
- Audit logging is enabled for the scoped production stack.

## Attested

- Security awareness training completion is documented for the current review window.

## Failed


## Stale Evidence


## Judgment Required

- The overall policy suite is adequate for the whole framework boundary.

## Evidence Missing

- Restore testing has been performed in the last quarter.

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

- Runtime-consumed claims: `5`
- Runtime status:
- typed control results live: `true`
- risk-acceptance defeasibility live: `true`
- discretionary-term typing live: `true`
- full minimal solver agreement proved: `true`
- Python verdict layer replaced: `true`

## Why This Example Exists

It is public-safe and synthetic, but it still demonstrates the core idea:

- some things should be proved,
- some should be attested,
- some remain judgment,
- and some are blocked by missing evidence.
