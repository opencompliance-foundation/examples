# Actor Ontology

## Current actor kinds

The current public corridor now distinguishes five actor kinds:

- `system`
- `human`
- `delegated_approver`
- `verifier_service`
- `independent_witness`

Only the first three currently appear inside public evidence-claim fixtures. The latter two appear in public signing and witness surfaces rather than being faked as evidence claims.

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

Attestation claim types:

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

## Trust-policy layer

Evidence claims now carry a `trustPolicyRef`, and signed attestations now carry signer metadata that ties back to that policy:

- `signerRole`
- `signedAt`
- `trustPolicyId`
- `delegatedBy` and `delegationScope` where delegation is required

The current public registry is published in `open-specs/actor-trust-policies.json`.

## Current validation rules

System claims must carry:

- a `system` actor,
- a `trustPolicyRef` of `oc.trust.system-export`,
- provenance fields,
- and mapped control identifiers.

Owner attestations must carry:

- a `human` actor,
- a matching owner-attestation trust policy,
- signer role and signed time,
- provenance fields,
- and mapped control identifiers.

Delegated attestations must carry:

- a `delegated_approver` actor,
- a matching delegated trust policy,
- signer role and signed time,
- explicit `delegatedBy` and `delegationScope`,
- provenance fields,
- and mapped control identifiers.

## Current boundary

This ontology is intentionally narrow.

It still does not yet model:

- external auditor evidence claims as a first public corridor,
- certificate-body or CPA-firm opinion objects,
- or live identity-provider-backed signer verification.

It is now strong enough to reject incomplete delegated attestations deterministically, keep verifier and witness identities explicit in public artifacts, and stop pretending every signed claim is the same kind of human statement.
