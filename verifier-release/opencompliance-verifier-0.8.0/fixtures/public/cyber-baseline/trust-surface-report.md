# ExampleCo Cyber Baseline Trust-Surface Report

**Bundle:** `exampleco-cyber-baseline-bundle-2026-03-24`  
**Profile:** `cyber_baseline_corridor`

## Executive Summary

This synthetic example shows a wider OpenCompliance corridor without pretending the corridor is complete:

- `5` proved claims
- `0` attested claims
- `0` failed claims
- `0` stale-evidence claims
- `0` judgment-required claims
- `0` evidence-missing claims

## Proved

- Administrative identities require MFA and conditional access for the scoped managed admin boundary.
- The inbound network boundary defaults to deny and exposes only declared ingress ports.
- Secure baseline configuration is applied and insecure defaults are absent in the managed device set.
- Supported versions are in use and no critical security updates are overdue in the managed device set.
- Malware protection is enabled, current, and tamper-protected on the managed device set.

## Attested


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

- Runtime-consumed claims: `5`
- Runtime status:
- typed control results live: `true`
- risk-acceptance defeasibility live: `true`
- discretionary-term typing live: `true`
- full minimal solver agreement proved: `false`
- Python verdict layer replaced: `true`

## Why This Example Exists

It is public-safe and synthetic, and it exists to show a clean issued corridor for a narrow cyber hygiene baseline:

- five machine-checkable controls,
- a certificate path that stays narrow and explicit,
- crosswalks into adjacent public cyber frameworks without claiming full-framework certification,
- and a reusable ExampleCo pack that other teams can adapt without leaking real estate or endpoint data.
