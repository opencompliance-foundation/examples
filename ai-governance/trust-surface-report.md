# ExampleCo AI Governance Trust-Surface Report

**Bundle:** `exampleco-ai-governance-bundle-2026-03-24`  
**Profile:** `ai_governance_corridor`

## Executive Summary

This synthetic example shows a wider OpenCompliance corridor without pretending the corridor is complete:

- `1` proved claim
- `4` attested claims
- `0` failed claims
- `0` stale-evidence claims
- `0` judgment-required claims
- `0` evidence-missing claims

## Proved

- AI-generated content disclosure is enabled and enforcement checks are passing on the public assistant surface.

## Attested

- AI system intended use, deployment context, and named owner are documented for the current review window.
- AI risk management process and risk tolerances are documented for the current review window.
- Human oversight roles, escalation path, and override responsibility are documented for the current review window.
- Post-deployment monitoring ownership and incident escalation are documented for the current review window.

## Failed


## Stale Evidence


## Judgment Required


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

It is public-safe and synthetic, and it exists to show what an honest AI governance corridor can look like today:

- documentary governance evidence stays explicitly documentary,
- disclosure configuration stays machine-checkable,
- the issued artifact is still narrow and scoped rather than pretending to certify the whole AI Act,
- and the corridor can be replayed and audited like the cyber examples.
