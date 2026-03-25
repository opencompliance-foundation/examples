# ExampleCo Stale-Evidence Trust-Surface Report

**Bundle:** `exampleco-stale-bundle-2026-03-24`  
**Profile:** `stale_freshness_corridor`

## Executive Summary

This synthetic example shows a wider OpenCompliance corridor without pretending the corridor is complete:

- `1` proved claim
- `1` attested claim
- `0` failed claims
- `2` stale-evidence claims
- `0` judgment-required claims
- `0` evidence-missing claims

## Proved

- Administrative identities require MFA in the scoped production environment.

## Attested

- Restore testing has been performed in the declared review window.

## Failed


## Stale Evidence

- Audit logging is enabled for the scoped production stack.
- Security awareness training completion is documented for the current review window.

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

- Runtime-consumed claims: `4`
- Runtime status:
- typed control results live: `true`
- risk-acceptance defeasibility live: `true`
- discretionary-term typing live: `true`
- full minimal solver agreement proved: `false`
- Python verdict layer replaced: `true`

## Why This Example Exists

It is public-safe and synthetic, and it exists to prove the verifier downgrades expired evidence instead of silently accepting it:

- one claim is still proved,
- one claim is still attested,
- two claims are blocked because their evidence expired,
- and the corridor therefore returns a punch-list rather than a certificate.
