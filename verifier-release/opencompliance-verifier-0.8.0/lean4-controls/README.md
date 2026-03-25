# OpenCompliance Lean4 Controls

This directory is the private source of truth for the first public export to `opencompliance-foundation/lean4-controls`.

It is intentionally narrow.

## What exists today

- a buildable Lean 4 package,
- a formal corridor for scoped MFA, typed periodic access-review exports, scoped password policy, managed web-application-firewall attachment, unique named infrastructure identities, customer and environment segmentation, audit logging, centralized monitoring, TLS ingress, managed ingress-boundary attachment, administrative-ingress restriction, plaintext-transport disablement, encryption at rest for scoped customer data stores, machine credential hygiene, approved-region boundaries, backup scheduling predicates, default-branch protections, CI workflow policy constraints, secure baseline configuration, supported security updates, endpoint malware protection, AI-generated-content disclosure configuration, and a default-deny cyber-baseline network boundary,
- example modules aligned to the public synthetic proof bundles,
- and a LegalLean-backed typed layer for `FormalisationBoundary`, risk acceptance defeats, discretionary terms, typed audit logging, a reduced-corpus compliance solver, and a public-corridor runtime layer whose decisions now drive every current public synthetic fixture.

## Current corridor

- `AdministrativeMfaSatisfied`
- `TypedPeriodicAccessReviewExportPresent`
- `ScopedPasswordPolicySatisfied`
- `WebApplicationFirewallSatisfied`
- `UniqueInfrastructureAuthenticationSatisfied`
- `EnvironmentSegmentationSatisfied`
- `AuditLoggingEnabled`
- `RetentionWindowDeclared`
- `NarrowAuditLoggingCorridor`
- `CentralizedMonitoringSatisfied`
- `TlsIngressSatisfied`
- `ManagedIngressBoundaryAttached`
- `AdministrativeIngressRestricted`
- `PlaintextTransportDisabled`
- `EncryptionAtRestSatisfied`
- `NoUserManagedServiceAccountKeys`
- `ApprovedRegionBoundarySatisfied`
- `BackupSnapshotScheduleSatisfied`
- `DefaultBranchProtectionsEnforced`
- `CiWorkflowPolicyConstrained`
- `SecureConfigurationBaselineSatisfied`
- `SupportedSecurityUpdatesCurrent`
- `MalwareProtectionBaselineSatisfied`
- `AiGeneratedContentDisclosureConfigured`
- `DefaultDenyNetworkBoundarySatisfied`

These are deliberately smaller than whole controls or whole frameworks.

## Current typed boundary layer

- `OpenCompliance.Controls.Typed.TypedIdentity`
- `OpenCompliance.Controls.Typed.TypedLogging`
- `OpenCompliance.Controls.Typed.RiskAcceptance`
- `OpenCompliance.Controls.Typed.DiscretionaryTerms`
- `OpenCompliance.Controls.Typed.ComplianceSolver`
- `OpenCompliance.Controls.Typed.PublicRuntime`

These modules do not widen the proved corridor automatically.
They now make the boundary between proof, attestation, defeat, and judgment
explicit in Lean and feed the runtime verdict path for the full current
public fixture set: `minimal`, `failed`, `stale`, `medium`, `issued`,
`cyber-baseline`, and `ai-governance`.

## Build

```sh
lake build
```

## Public example linkage

The example theorems in `OpenCompliance/Examples/Minimal.lean`, `OpenCompliance/Examples/Medium.lean`, `OpenCompliance/Examples/CyberBaseline.lean`, and `OpenCompliance/Examples/AiGovernance.lean` mirror the runtime facts in the public synthetic bundles under `examples/minimal/`, `examples/medium/`, `examples/cyber-baseline/`, and `examples/ai-governance/`. The medium example now also includes the typed access-review-export theorem, the default-branch-protection theorem, and the CI-policy theorem, while the cyber-baseline and AI examples cover secure baseline configuration, supported security updates, malware protection, and AI output disclosure.

## What does not exist yet

- no JSON or OSCAL ingestion,
- no broad control library,
- no proof that whole frameworks are satisfied,
- no reference verifier that turns live evidence into Lean values automatically,
- no claim that the current public runtime layer is yet a released external verifier or a full-framework solver.
