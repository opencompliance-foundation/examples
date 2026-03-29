# ExampleCo Medium Trust-Surface Report

**Bundle:** `exampleco-medium-bundle-2026-03-24`  
**Profile:** `medium_multiframework_corridor`

## Executive Summary

This synthetic example shows a wider OpenCompliance corridor without pretending the corridor is complete:

- `18` proved claims
- `45` attested claims
- `0` failed claims
- `0` stale-evidence claims
- `19` judgment-required claims
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
- Scoped remote access traverses the declared remote-access path with device posture controls bounded for the systems in scope.

## Attested

- Security awareness completion is documented for the current review period.
- A restore exercise is documented inside the declared review window.
- The processor register is current and DPA coverage is declared for the reviewed subprocessors.
- The DSR runbook is approved and has a named owner for the current review window.
- The lawful-basis register is current and records purpose boundaries for the in-scope personal-data processing.
- The external privacy notice is published and links people to the current rights-handling path.
- A current privacy impact assessment exists for the in-scope product and names a sign-off owner.
- The production change-review policy is approved and declares an emergency change path for the current review window.
- Access review closure and high-risk exception resolution are attested for the current review window.
- Monitoring review cadence, ownership, and retention operations are attested for the scoped production telemetry program.
- Configuration exceptions are current, owned, and not already expired in the current review window.
- Patch exceptions declare compensating controls and no declared exception is already expired in the current review window.
- The incident response runbook is approved, owned, and current for the declared review window.
- Incident escalation contacts and notification paths are current for the declared review window.
- High-risk vendor agreements carry the required security and privacy terms for the current review window.
- Data retention schedules and exception handling are documented and current for the scoped lifecycle program.
- Scoped service and supplier agreements carry the declared security commitment terms for the current review window.
- Ownership, review cadence, and exception handling are current for scoped security commitment governance.
- Outsourced development relationships carry current security requirements for the declared review window.
- Oversight and exception handling are current for scoped outsourced development relationships.
- A current intake path exists for reported security concerns relevant to the scoped service operations.
- Tracking, ownership, and resolution follow-up are current for the scoped security-concern process.
- A current remote-working procedure covers incident reporting for the scoped workforce and review window.
- A current register of legal, regulatory, contractual, and compliance requirements is attested for the scoped ISMS surface.
- Compliance requirement review cadence, ownership, and update handling are current for the scoped inventory.
- A current register of interested parties and stakeholder groups is attested for the scoped ISMS surface.
- Stakeholder expectations, obligations, and review ownership are current for the scoped ISMS surface.
- Current project-security requirements are defined for the project types in the scoped delivery portfolio.
- Project-security review and exception tracking are current for the scoped delivery portfolio.
- Current customer support channels are documented and reachable for the scoped service surface.
- Support staffing, escalation ownership, and response governance are current for the scoped service surface.
- A current intellectual-property policy or requirement set is attested for the scoped service and workforce surface.
- Issue tracking, handling rules, and ownership are current for scoped intellectual-property obligations.
- A current corrective-action process is defined with named ownership for the scoped ISMS improvement cycle.
- Corrective-action follow-up and remediation ownership are current for the scoped improvement cycle.
- A current code-of-conduct acknowledgement set exists for the scoped workforce population.
- Refresh triggers and disciplinary pathways are current for the scoped workforce conduct program.
- A current disciplinary policy covers the scoped workforce populations.
- Disciplinary action records are current for the scoped breach-review window.
- A current internal-audit program and schedule exist for the scoped control surface.
- Findings and follow-up are current for the scoped internal-audit cycle.
- A current clear-desk and clear-screen policy exists for the scoped work areas.
- Communication and coverage are current for the scoped clear-desk and clear-screen program.
- Current participation exists in the scoped external security or special-interest groups.
- Ownership and dissemination are current for scoped external security inputs.

## Failed


## Stale Evidence


## Judgment Required

- Privacy-by-design adequacy has been demonstrated for the full product change process.
- Patch cadence and exception thresholds are adequate for the in-scope production assets.
- Vendor tiering, review cadence, and inherited-control allocation are adequate for the in-scope dependency set.
- Retention periods, exception scope, and deletion adequacy are sufficient for the in-scope data lifecycle surface.
- The scoped security commitments and their governance are adequate for the supplier and transfer risks in scope.
- The outsourced development model is adequate for the scoped third-party delivery risks.
- The scoped handling model for reported security concerns is adequate to triage, resolve, and learn from the issues that matter.
- The scoped remote-working model is adequate for the device, workspace, and incident-reporting risks that matter.
- The scoped compliance inventory is adequate for the legal, regulatory, and contractual obligations that materially affect the ISMS.
- The scoped stakeholder-management model is adequate for the interested parties and expectations that materially affect the ISMS.
- The scoped project-security model is adequate for integrating security into the project types and lifecycle stages that matter.
- The scoped customer-support model is adequate for the channel, escalation, and service risks that matter.
- The scoped intellectual-property posture is adequate to protect proprietary material and avoid misuse of third-party rights in scope.
- The scoped continual-improvement model is adequate to identify, prioritize, and close the issues that matter.
- The scoped workforce conduct model is adequate for the behavioural and security risks that matter.
- The scoped disciplinary model is adequate to respond proportionately and consistently when relevant breaches occur.
- The scoped internal-audit model is adequate to provide independent, useful assurance over the controls that matter.
- The scoped workspace hygiene model is adequate to reduce inadvertent physical disclosure and shoulder-surfing risks.
- The scoped security-community participation model is adequate to turn relevant external insights into useful internal action.

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
- `OpenCompliance.Controls.Typed.PublicRuntime` covers `formalDecision`, `documentaryDecision`, `judgmentDecision`, `public_corridor_runtime_claim_decisions`

- Runtime-consumed claims: `83`
- Runtime status:
- typed control results live: `true`
- risk-acceptance defeasibility live: `true`
- discretionary-term typing live: `true`
- full minimal solver agreement proved: `false`
- Python verdict layer replaced: `true`

## Why This Example Exists

It is public-safe and synthetic, but it demonstrates a more serious corridor than the minimal pack:

- multi-framework family mappings,
- explicit control references back into the synthetic OpenCompliance catalog,
- a cleaner split between runtime proofs and signed attestations,
- a deeper ISO 27001 and SOC 2 overlap slice for perimeter, centralized monitoring, ingress-boundary, and transport controls,
- a first public mixed-control decomposition for change management,
- and a still-honest boundary where legal or adequacy judgment remains human.
