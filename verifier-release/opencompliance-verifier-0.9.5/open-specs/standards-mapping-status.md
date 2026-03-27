# Standards Mapping Status

This file is a public-safe status view for the ISO 27001 and SOC 2 mapping-completion program inside OpenCompliance.

It is intentionally narrower than a private exact-anchor corpus. It says what exists, what is blocked, and what remains to be reviewed.

## ISO 27001

- Source availability: `blocked_nonpublic_source_review`
- Seed controls touching framework: `85`
- Framework anchors in private depth corpus: `423`
- Private atomic obligations: `243`
- Mapped public controls: `85`
- Implemented public controls: `38`
- Planned public controls: `47`
- Lean-backed public controls: `21`
- Blocked exact-anchor public controls: `35`
- Family rollout entries: `29`

### Workstreams

- `Authoritative-source decomposition`: `private_seed_coverage_complete_public_exact_pending`
  - Current state: All 85 seed controls touching ISO 27001 are covered in the private depth corpus, spanning 243 atomic obligations in the current framework-depth view.
  - Remaining work: Replace seed-derived decomposition with authoritative-source-reviewed decomposition at the clause, Annex A, criterion, or point-of-focus level.
  - Blocked by: `licensed_exact_anchor_review`
- `Source-to-atom mapping graph`: `machine_readable_private_graph_available`
  - Current state: The private decomposition pilot currently persists 258 atomic obligations and source-linked control targets across the combined ISO 27001 / SOC 2 bridge.
  - Remaining work: Keep promoting publication-safe graph metadata without exposing proprietary source text.
- `Exact-anchor review`: `blocked_licensed_review_required`
  - Current state: 35 currently promoted controls for ISO 27001 are explicitly marked as blocked for public exact-anchor publication pending licensed review.
  - Remaining work: Run licensed-source review against the authoritative standard text and replace blocker-only records with reviewed exact anchors where publication is defensible.
  - Blocked by: `licensed_exact_anchor_review`
- `Public-control normalization`: `partial`
  - Current state: 85 public controls map to ISO 27001, with 38 already exercised by public fixtures and 47 still planned.
  - Remaining work: Promote or retire the remaining planned controls so every publication-safe atomic obligation lands in an explicit public control or an explicit non-coverage statement.
- `Typed claim coverage`: `partial`
  - Current state: The private bridge currently reuses 68 existing claim types and still references 87 planned future claim types.
  - Remaining work: Close the remaining typed evidence gaps for non-judgment atoms before promoting those controls into the public verifier surface.
- `Lean coverage`: `partial`
  - Current state: 21 promoted public controls currently have Lean-backed coverage, while the private framework-depth view tracks 58 decidable atoms for the framework.
  - Remaining work: Promote additional decidable atoms into Lean only when the public control boundary, claim schema, and exact-anchor story are stable enough to avoid bluffing.
- `Boundary inventory`: `private_boundary_inventory_available`
  - Current state: The current framework-depth split for ISO 27001 is 122 attestation atoms and 63 judgment atoms.
  - Remaining work: Keep the attestation and judgment routes explicit as public controls, claim schemas, and trust-surface outputs widen.
- `Fixture rollout`: `partial`
  - Current state: 29 framework families now have a rollout matrix, but only 38 of 85 mapped controls are currently exercised in public fixtures.
  - Remaining work: Grow fixture coverage family by family, keeping planned controls explicit until they have source exports, typed claims, verifier outputs, and conformance coverage.
- `Publication model`: `published_program`
  - Current state: A machine-readable proprietary-framework publication model now records what can be published publicly, what stays private, and where licensed review is required.
  - Remaining work: Use the published model consistently for future proprietary-framework waves.
- `External review`: `published_program`
  - Current state: A machine-readable external review and conformance program now records the required reviewer roles, tracks, and pass gates for ISO 27001 and SOC 2 mapping work.
  - Remaining work: Run the external review program once licensed exact-anchor review materials exist.
  - Blocked by: `licensed_exact_anchor_review`

### Family rollout

- `awareness_and_training`: mapped `1`, implemented `1`, planned `0`, Lean-backed `0`
- `backup_and_recovery`: mapped `4`, implemented `4`, planned `0`, Lean-backed `1`
- `compliance_requirements`: mapped `3`, implemented `0`, planned `3`, Lean-backed `0`
- `continual_improvement_and_corrective_action`: mapped `3`, implemented `0`, planned `3`, Lean-backed `0`
- `cryptographic_key_management`: mapped `1`, implemented `1`, planned `0`, Lean-backed `1`
- `data_retention_and_deletion`: mapped `3`, implemented `1`, planned `2`, Lean-backed `0`
- `disciplinary_process`: mapped `3`, implemented `0`, planned `3`, Lean-backed `0`
- `encryption_at_rest`: mapped `1`, implemented `1`, planned `0`, Lean-backed `1`
- `identity_and_access_management`: mapped `5`, implemented `5`, planned `0`, Lean-backed `4`
- `incident_response`: mapped `2`, implemented `2`, planned `0`, Lean-backed `0`
- `intellectual_property_rights`: mapped `3`, implemented `0`, planned `3`, Lean-backed `0`
- `internal_audit_program`: mapped `3`, implemented `0`, planned `3`, Lean-backed `0`
- `isms_context_and_scope`: mapped `3`, implemented `0`, planned `3`, Lean-backed `0`
- `isms_stakeholder_management`: mapped `3`, implemented `0`, planned `3`, Lean-backed `0`
- `logging_and_monitoring`: mapped `3`, implemented `3`, planned `0`, Lean-backed `2`
- `malware_protection`: mapped `1`, implemented `1`, planned `0`, Lean-backed `1`
- `network_security`: mapped `6`, implemented `6`, planned `0`, Lean-backed `6`
- `physical_and_environmental_security`: mapped `3`, implemented `0`, planned `3`, Lean-backed `0`
- `physical_workspace_hygiene`: mapped `3`, implemented `0`, planned `3`, Lean-backed `0`
- `project_security`: mapped `3`, implemented `0`, planned `3`, Lean-backed `0`
- `remote_working`: mapped `3`, implemented `0`, planned `3`, Lean-backed `0`
- `risk_management`: mapped `3`, implemented `3`, planned `0`, Lean-backed `0`
- `secure_configuration`: mapped `2`, implemented `2`, planned `0`, Lean-backed `1`
- `secure_development_and_change_control`: mapped `4`, implemented `4`, planned `0`, Lean-backed `2`
- `security_community_participation`: mapped `3`, implemented `0`, planned `3`, Lean-backed `0`
- `segregation_and_environment_separation`: mapped `1`, implemented `1`, planned `0`, Lean-backed `1`
- `supplier_relationships`: mapped `6`, implemented `3`, planned `3`, Lean-backed `0`
- `vulnerability_and_patch_management`: mapped `3`, implemented `3`, planned `0`, Lean-backed `1`
- `workforce_conduct`: mapped `3`, implemented `0`, planned `3`, Lean-backed `0`

## SOC 2

- Source availability: `blocked_nonpublic_source_review`
- Seed controls touching framework: `76`
- Framework anchors in private depth corpus: `175`
- Private atomic obligations: `215`
- Mapped public controls: `58`
- Implemented public controls: `38`
- Planned public controls: `20`
- Lean-backed public controls: `21`
- Blocked exact-anchor public controls: `35`
- Family rollout entries: `18`

### Workstreams

- `Authoritative-source decomposition`: `private_seed_coverage_complete_public_exact_pending`
  - Current state: All 76 seed controls touching SOC 2 are covered in the private depth corpus, spanning 215 atomic obligations in the current framework-depth view.
  - Remaining work: Replace seed-derived decomposition with authoritative-source-reviewed decomposition at the clause, Annex A, criterion, or point-of-focus level.
  - Blocked by: `licensed_exact_anchor_review`
- `Source-to-atom mapping graph`: `machine_readable_private_graph_available`
  - Current state: The private decomposition pilot currently persists 258 atomic obligations and source-linked control targets across the combined ISO 27001 / SOC 2 bridge.
  - Remaining work: Keep promoting publication-safe graph metadata without exposing proprietary source text.
- `Exact-anchor review`: `blocked_licensed_review_required`
  - Current state: 35 currently promoted controls for SOC 2 are explicitly marked as blocked for public exact-anchor publication pending licensed review.
  - Remaining work: Run licensed-source review against the authoritative standard text and replace blocker-only records with reviewed exact anchors where publication is defensible.
  - Blocked by: `licensed_exact_anchor_review`
- `Public-control normalization`: `partial`
  - Current state: 58 public controls map to SOC 2, with 38 already exercised by public fixtures and 20 still planned.
  - Remaining work: Promote or retire the remaining planned controls so every publication-safe atomic obligation lands in an explicit public control or an explicit non-coverage statement.
- `Typed claim coverage`: `partial`
  - Current state: The private bridge currently reuses 68 existing claim types and still references 87 planned future claim types.
  - Remaining work: Close the remaining typed evidence gaps for non-judgment atoms before promoting those controls into the public verifier surface.
- `Lean coverage`: `partial`
  - Current state: 21 promoted public controls currently have Lean-backed coverage, while the private framework-depth view tracks 56 decidable atoms for the framework.
  - Remaining work: Promote additional decidable atoms into Lean only when the public control boundary, claim schema, and exact-anchor story are stable enough to avoid bluffing.
- `Boundary inventory`: `private_boundary_inventory_available`
  - Current state: The current framework-depth split for SOC 2 is 105 attestation atoms and 54 judgment atoms.
  - Remaining work: Keep the attestation and judgment routes explicit as public controls, claim schemas, and trust-surface outputs widen.
- `Fixture rollout`: `partial`
  - Current state: 18 framework families now have a rollout matrix, but only 38 of 58 mapped controls are currently exercised in public fixtures.
  - Remaining work: Grow fixture coverage family by family, keeping planned controls explicit until they have source exports, typed claims, verifier outputs, and conformance coverage.
- `Publication model`: `published_program`
  - Current state: A machine-readable proprietary-framework publication model now records what can be published publicly, what stays private, and where licensed review is required.
  - Remaining work: Use the published model consistently for future proprietary-framework waves.
- `External review`: `published_program`
  - Current state: A machine-readable external review and conformance program now records the required reviewer roles, tracks, and pass gates for ISO 27001 and SOC 2 mapping work.
  - Remaining work: Run the external review program once licensed exact-anchor review materials exist.
  - Blocked by: `licensed_exact_anchor_review`

### Family rollout

- `access_control`: mapped `5`, implemented `5`, planned `0`, Lean-backed `4`
- `backup_and_recovery`: mapped `4`, implemented `4`, planned `0`, Lean-backed `1`
- `change_management`: mapped `4`, implemented `4`, planned `0`, Lean-backed `2`
- `customer_support_operations`: mapped `3`, implemented `0`, planned `3`, Lean-backed `0`
- `data_retention_and_deletion`: mapped `3`, implemented `1`, planned `2`, Lean-backed `0`
- `encryption_at_rest`: mapped `1`, implemented `1`, planned `0`, Lean-backed `1`
- `endpoint_protection`: mapped `1`, implemented `1`, planned `0`, Lean-backed `1`
- `environment_and_tenant_separation`: mapped `1`, implemented `1`, planned `0`, Lean-backed `1`
- `ethics_and_integrity`: mapped `3`, implemented `0`, planned `3`, Lean-backed `0`
- `incident_response`: mapped `5`, implemented `2`, planned `3`, Lean-backed `0`
- `key_management`: mapped `1`, implemented `1`, planned `0`, Lean-backed `1`
- `logging_monitoring`: mapped `3`, implemented `3`, planned `0`, Lean-backed `2`
- `network_security`: mapped `6`, implemented `6`, planned `0`, Lean-backed `6`
- `risk_management`: mapped `3`, implemented `3`, planned `0`, Lean-backed `0`
- `security_awareness`: mapped `1`, implemented `1`, planned `0`, Lean-backed `0`
- `system_operations_and_hardening`: mapped `2`, implemented `2`, planned `0`, Lean-backed `1`
- `vendor_management`: mapped `9`, implemented `3`, planned `6`, Lean-backed `0`
- `vulnerability_management`: mapped `3`, implemented `3`, planned `0`, Lean-backed `1`

