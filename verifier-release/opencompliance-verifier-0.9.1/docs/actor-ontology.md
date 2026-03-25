# Actor Ontology

## Current actor kinds

The current synthetic corridor uses two actor kinds:

- `system`
- `human`

This is deliberately small.

## Current claim-type split

Machine evidence claim types:

- `identity_mfa_enforcement`
- `audit_logging_state`
- `tls_ingress_configuration`
- `service_account_key_hygiene`
- `approved_region_deployment`
- `backup_snapshot_schedule`
- `access_review_export`
- `repo_branch_protection`
- `ci_workflow_policy`
- `network_firewall_boundary`
- `secure_configuration_state`
- `security_update_state`
- `malware_protection_state`
- `ai_content_labeling_state`

Human attestation claim types:

- `access_review_closure_attestation`
- `ai_context_attestation`
- `ai_human_oversight_attestation`
- `ai_monitoring_attestation`
- `ai_risk_management_attestation`
- `change_review_attestation`
- `configuration_exception_attestation`
- `incident_contact_matrix_attestation`
- `incident_response_runbook_attestation`
- `patch_exception_attestation`
- `training_attestation`
- `restore_test_attestation`
- `vendor_register_attestation`
- `vendor_security_terms_attestation`
- `dsr_runbook_attestation`

## Current validation rules

System claims must carry:

- a `system` actor,
- provenance fields,
- and mapped control identifiers.

Human attestations must carry:

- a `human` actor,
- freshness fields,
- signer identity and signature metadata,
- provenance fields,
- and mapped control identifiers.

## Current boundary

This ontology is intentionally narrow.

It does not yet model:

- delegated approval chains,
- organisation roles beyond simple human/system splits,
- external auditor identities,
- or richer signer trust policies.

It is enough to reject obviously incomplete claims deterministically in the current corridor.
