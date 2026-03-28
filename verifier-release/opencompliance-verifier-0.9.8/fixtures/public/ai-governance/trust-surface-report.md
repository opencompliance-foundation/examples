# ExampleCo AI Governance Trust-Surface Report

**Bundle:** `exampleco-ai-governance-bundle-2026-03-24`  
**Profile:** `ai_governance_corridor`

## Executive Summary

This synthetic example shows a wider OpenCompliance corridor without pretending the corridor is complete:

- `2` proved claims
- `9` attested claims
- `0` failed claims
- `0` stale-evidence claims
- `1` judgment-required claim
- `0` evidence-missing claims

## Proved

- AI-generated content disclosure is enabled and enforcement checks are passing on the public assistant surface.
- AI-generated content provenance metadata is enabled and verification checks are passing on the public assistant surface.

## Attested

- AI system intended use, deployment context, and named owner are documented for the current review window.
- AI risk management process and risk tolerances are documented for the current review window.
- Human oversight roles, escalation path, and override responsibility are documented for the current review window.
- Post-deployment monitoring ownership and incident escalation are documented for the current review window.
- AI evaluation scope, testing layers, and findings capture are documented for the current review window.
- AI data sources, quality criteria, and lineage stewardship are documented for the current review window.
- The lawful-basis and purpose register is current for the scoped AI-assisted processing path.
- A current privacy or AI impact assessment exists for the scoped AI-assisted processing path.
- High-impact human review triggers and a contest path are documented for the scoped AI-assisted decision path.

## Failed


## Stale Evidence


## Judgment Required

- The legality and contestability of significant-effect automated decisions have been fully demonstrated for every in-scope use case.

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

- Runtime-consumed claims: `12`
- Runtime status:
- typed control results live: `true`
- risk-acceptance defeasibility live: `true`
- discretionary-term typing live: `true`
- full minimal solver agreement proved: `false`
- Python verdict layer replaced: `true`

## Why This Example Exists

It is public-safe and synthetic, and it exists to show what an honest AI governance corridor can look like today:

- documentary governance evidence stays explicitly documentary,
- disclosure and provenance configuration stay machine-checkable,
- evaluation and data-governance evidence become visible without pretending they are theorems,
- the issued artifact is still narrow and scoped rather than pretending to certify the whole AI Act,
- and the corridor can be replayed and audited like the cyber examples.
