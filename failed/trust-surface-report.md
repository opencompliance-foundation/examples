# ExampleCo Failed Trust-Surface Report

**Bundle:** `exampleco-failed-bundle-2026-03-24`  
**Profile:** `failed_saas_corridor`

## Executive Summary

This synthetic example shows a wider OpenCompliance corridor without pretending the corridor is complete:

- `1` proved claim
- `1` attested claim
- `1` failed claim
- `0` stale-evidence claims
- `1` judgment-required claim
- `0` evidence-missing claims

## Proved

- Administrative identities require MFA in the scoped production environment.

## Attested

- Security awareness training completion is documented for the current review window.

## Failed

- Audit logging is enabled for the scoped production stack.

## Stale Evidence


## Judgment Required

- The overall policy suite is adequate for the whole framework boundary.

## Evidence Missing


## Typed Boundary Layer

The current public corridor uses `LegalLean` as its typed boundary vocabulary.

- Dependency package: `legal-lean`
- Live typed modules:
- `OpenCompliance.Controls.Typed.TypedIdentity` covers `FormalisationBoundary.formal`, `FormalisationBoundary.boundary`, `RequiresHumanDetermination`
- `OpenCompliance.Controls.Typed.RiskAcceptance` covers `Defeats`, `risk_acceptance_override`
- `OpenCompliance.Controls.Typed.DiscretionaryTerms` covers `Vague`, `judgment_boundary_inventory`
- `OpenCompliance.Controls.Typed.ComplianceSolver` covers `LegalLean.Solver`, `minimal_claim_corpus`

- Runtime status:
- typed control results live: `true`
- risk-acceptance defeasibility live: `true`
- discretionary-term typing live: `true`
- full minimal solver agreement proved: `false`
- Python verdict layer replaced: `false`

## Why This Example Exists

It is public-safe and synthetic, and it exists to prove the verifier can encode failure as data instead of crashing:

- one claim is still proved,
- one claim is present but failed,
- one claim is attested,
- and one claim remains judgment-routed.
