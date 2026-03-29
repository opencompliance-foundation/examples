from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .actor_ontology import (
    ACTOR_IDENTITY_BY_ID,
    ACTOR_TYPES,
    CONNECTOR_INGRESS_PROFILE_BY_ID,
    EVIDENCE_CLAIM_ACTOR_TYPES,
    SIGNED_ACTOR_TYPES,
    SYSTEM_EXPORT_POLICY_ID,
    TRUST_POLICY_BY_ID,
    evidence_claim_policy_ids,
    trust_policy_for_claim_type,
    validate_connector_ingress,
)

SYSTEM_CLAIM_TYPES = {
    "identity_mfa_enforcement",
    "infrastructure_auth_uniqueness_state",
    "password_policy_state",
    "web_application_firewall_state",
    "central_monitoring_state",
    "environment_segmentation_state",
    "audit_logging_state",
    "tls_ingress_configuration",
    "encryption_at_rest_state",
    "service_account_key_hygiene",
    "approved_region_deployment",
    "backup_snapshot_schedule",
    "access_review_export",
    "repo_branch_protection",
    "ci_workflow_policy",
    "remote_access_posture_state",
    "network_firewall_boundary",
    "secure_configuration_state",
    "security_update_state",
    "malware_protection_state",
    "ai_content_labeling_state",
    "ai_content_provenance_state",
    "ai_task_envelope_state",
    "ai_rights_ready_run_trace_state",
    "privacy_notice_publication_state",
}

HUMAN_CLAIM_TYPES = {
    "access_review_closure_attestation",
    "ai_context_attestation",
    "ai_human_oversight_attestation",
    "ai_human_review_trigger_attestation",
    "ai_monitoring_attestation",
    "ai_risk_management_attestation",
    "ai_evaluation_attestation",
    "ai_data_quality_attestation",
    "ai_supplier_transfer_attestation",
    "configuration_exception_attestation",
    "compliance_requirement_register_attestation",
    "compliance_requirement_review_attestation",
    "code_of_conduct_attestation",
    "conduct_governance_attestation",
    "corrective_action_followup_attestation",
    "corrective_action_process_attestation",
    "customer_support_channel_attestation",
    "customer_support_governance_attestation",
    "clear_desk_screen_policy_attestation",
    "clear_desk_screen_coverage_attestation",
    "lawful_basis_register_attestation",
    "privacy_notice_attestation",
    "privacy_impact_assessment_attestation",
    "data_retention_schedule_attestation",
    "disciplinary_action_attestation",
    "disciplinary_policy_attestation",
    "dsr_runbook_attestation",
    "incident_contact_matrix_attestation",
    "incident_response_runbook_attestation",
    "internal_audit_execution_attestation",
    "internal_audit_program_attestation",
    "intellectual_property_issue_attestation",
    "intellectual_property_policy_attestation",
    "isms_stakeholder_obligation_attestation",
    "isms_stakeholder_register_attestation",
    "monitoring_review_attestation",
    "outsourced_development_requirement_attestation",
    "outsourced_development_review_attestation",
    "patch_exception_attestation",
    "project_security_requirement_attestation",
    "project_security_review_attestation",
    "remote_working_attestation",
    "security_commitment_governance_attestation",
    "security_commitment_terms_attestation",
    "security_concern_intake_attestation",
    "security_concern_resolution_attestation",
    "security_community_membership_attestation",
    "security_community_output_review_attestation",
    "training_attestation",
    "restore_test_attestation",
    "vendor_register_attestation",
    "vendor_security_terms_attestation",
    "change_review_attestation",
}


def _reason(code: str, field_path: str, message: str) -> dict[str, str]:
    return {
        "code": code,
        "fieldPath": field_path,
        "message": message,
    }


def _parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def validate_claim(raw: dict[str, Any]) -> list[dict[str, str]]:
    reasons: list[dict[str, str]] = []
    claim_type = raw.get("claimType")
    actor = raw.get("actor", {})
    actor_type = actor.get("actorType")
    trust_policy_ref = raw.get("trustPolicyRef")

    if claim_type not in SYSTEM_CLAIM_TYPES | HUMAN_CLAIM_TYPES:
        reasons.append(
            _reason(
                "unknown_claim_type",
                "claimType",
                "Claim type is not in the current OpenCompliance synthetic corridor registry.",
            )
        )
        return reasons

    if actor_type not in ACTOR_TYPES:
        reasons.append(
            _reason(
                "unknown_actor_type",
                "actor.actorType",
                "Actor type is outside the current OpenCompliance actor ontology.",
            )
        )
    elif actor_type not in EVIDENCE_CLAIM_ACTOR_TYPES:
        reasons.append(
            _reason(
                "actor_type_not_for_evidence_claim",
                "actor.actorType",
                "Evidence claims may only use system, human, or delegated_approver actor kinds.",
            )
        )

    expected_policy_id = trust_policy_for_claim_type(claim_type)
    if not trust_policy_ref:
        reasons.append(
            _reason(
                "missing_trust_policy",
                "trustPolicyRef",
                "Evidence claims must declare a trust-policy reference.",
            )
        )
    elif trust_policy_ref not in evidence_claim_policy_ids():
        reasons.append(
            _reason(
                "unknown_trust_policy",
                "trustPolicyRef",
                "Evidence claims must reference a known evidence-claim trust policy.",
            )
        )
    elif trust_policy_ref != expected_policy_id:
        reasons.append(
            _reason(
                "unexpected_trust_policy",
                "trustPolicyRef",
                "Claim type does not match the declared trust policy.",
            )
        )

    actor_id = actor.get("actorId")
    identity = None
    if not actor_id:
        reasons.append(
            _reason(
                "missing_actor_identity",
                "actor.actorId",
                "Evidence claims must reference a known actor identity.",
            )
        )
    else:
        identity = ACTOR_IDENTITY_BY_ID.get(actor_id)
        if identity is None:
            reasons.append(
                _reason(
                    "unknown_actor_identity",
                    "actor.actorId",
                    "Actor identity is outside the current OpenCompliance synthetic identity registry.",
                )
            )
        else:
            if actor_type and identity["actorType"] != actor_type:
                reasons.append(
                    _reason(
                        "actor_identity_type_mismatch",
                        "actor.actorType",
                        "Actor type does not match the registered actor identity.",
                    )
                )
            if trust_policy_ref and trust_policy_ref not in set(identity["trustPolicyIds"]):
                reasons.append(
                    _reason(
                        "actor_identity_policy_mismatch",
                        "trustPolicyRef",
                        "Claim trust policy is not allowed for the registered actor identity.",
                    )
                )
            default_actor_role = identity.get("defaultActorRole")
            if actor.get("actorRole") and default_actor_role and actor["actorRole"] != default_actor_role:
                reasons.append(
                    _reason(
                        "actor_identity_role_mismatch",
                        "actor.actorRole",
                        "Actor role does not match the registered actor identity.",
                    )
                )

    if claim_type in SYSTEM_CLAIM_TYPES and actor_type != "system":
        reasons.append(
            _reason(
                "actor_type_mismatch",
                "actor.actorType",
                "Machine evidence claim types must be produced by a system actor.",
            )
        )
    if claim_type in SYSTEM_CLAIM_TYPES and actor_id and identity is not None:
        provenance = raw.get("provenance") or {}
        source_system = raw.get("sourceSystem")
        collection_method = provenance.get("collectionMethod")
        source_path = provenance.get("sourcePath")
        if actor_id not in CONNECTOR_INGRESS_PROFILE_BY_ID:
            reasons.append(
                _reason(
                    "missing_connector_ingress_profile",
                    "actor.actorId",
                    "System evidence claims must use a registered connector ingress profile.",
                )
            )
        elif not source_system or not collection_method or not source_path:
            reasons.append(
                _reason(
                    "missing_connector_ingress_fields",
                    "provenance",
                    "System evidence claims must carry sourceSystem, provenance.collectionMethod, and provenance.sourcePath for ingress review.",
                )
            )
        else:
            try:
                validate_connector_ingress(
                    actor_id,
                    claim_type=claim_type,
                    source_system=source_system,
                    collection_method=collection_method,
                    source_path=source_path,
                )
            except ValueError as exc:
                reasons.append(
                    _reason(
                        "connector_ingress_mismatch",
                        "provenance",
                        str(exc),
                    )
                )
    if claim_type in HUMAN_CLAIM_TYPES and trust_policy_ref in TRUST_POLICY_BY_ID:
        policy = TRUST_POLICY_BY_ID[trust_policy_ref]
        if actor_type not in set(policy["allowedActorTypes"]):
            reasons.append(
                _reason(
                    "actor_type_mismatch",
                    "actor.actorType",
                    "Attestation claim types must be produced by an actor kind allowed by the declared trust policy.",
                )
            )
        if not actor.get("actorRole"):
            reasons.append(
                _reason(
                    "missing_actor_role",
                    "actor.actorRole",
                    "Attestation claims must carry an actor role for trust-policy review.",
                )
            )

    provenance = raw.get("provenance")
    for field_name in ("exportId", "collectionMethod", "sourcePath", "digestAlgorithm"):
        if not provenance or not provenance.get(field_name):
            reasons.append(
                _reason(
                    "missing_provenance",
                    f"provenance.{field_name}",
                    "Typed evidence claims must carry provenance for deterministic chain-of-custody review.",
                )
            )

    freshness = raw.get("freshness")
    freshness_values: dict[str, datetime] = {}
    for field_name in ("evaluatedAt", "expiresAt"):
        if not freshness or not freshness.get(field_name):
            reasons.append(
                _reason(
                    "missing_freshness",
                    f"freshness.{field_name}",
                    "Typed evidence claims must carry an evaluation time and expiry.",
                )
            )
            continue
        try:
            freshness_values[field_name] = _parse_timestamp(freshness[field_name])
        except ValueError:
            reasons.append(
                _reason(
                    "invalid_freshness",
                    f"freshness.{field_name}",
                    "Freshness timestamps must be valid ISO 8601 date-time strings.",
                )
            )
    if set(freshness_values) == {"evaluatedAt", "expiresAt"} and freshness_values["evaluatedAt"] > freshness_values["expiresAt"]:
        reasons.append(
            _reason(
                "freshness_window_invalid",
                "freshness",
                "freshness.evaluatedAt must not be later than freshness.expiresAt.",
            )
        )

    if claim_type in HUMAN_CLAIM_TYPES:
        signer = raw.get("signer")
        for field_name in ("signerId", "signerType", "signatureType", "signedAt", "signerRole", "trustPolicyId"):
            if not signer or not signer.get(field_name):
                reasons.append(
                    _reason(
                        "missing_signer",
                        f"signer.{field_name}",
                        "Human attestations must carry signer identity and signature metadata.",
                    )
                )
        if signer:
            signer_type = signer.get("signerType")
            if signer_type not in SIGNED_ACTOR_TYPES:
                reasons.append(
                    _reason(
                        "unknown_signer_type",
                        "signer.signerType",
                        "Signer type is outside the current OpenCompliance signing actor ontology.",
                    )
                )
            signer_id = signer.get("signerId")
            signer_identity = ACTOR_IDENTITY_BY_ID.get(signer_id) if signer_id else None
            if signer_id and signer_identity is None:
                reasons.append(
                    _reason(
                        "unknown_signer_identity",
                        "signer.signerId",
                        "Signer identity is outside the current OpenCompliance synthetic identity registry.",
                    )
                )
            elif signer_identity is not None:
                if signer_type and signer_identity["actorType"] != signer_type:
                    reasons.append(
                        _reason(
                            "signer_identity_type_mismatch",
                            "signer.signerType",
                            "Signer type does not match the registered signer identity.",
                        )
                    )
                default_signer_role = signer_identity.get("defaultSignerRole")
                if signer.get("signerRole") and default_signer_role and signer["signerRole"] != default_signer_role:
                    reasons.append(
                        _reason(
                            "signer_identity_role_mismatch",
                            "signer.signerRole",
                            "Signer role does not match the registered signer identity.",
                        )
                    )
                if signer.get("trustPolicyId") and signer["trustPolicyId"] not in set(signer_identity["trustPolicyIds"]):
                    reasons.append(
                        _reason(
                            "signer_identity_policy_mismatch",
                            "signer.trustPolicyId",
                            "Signer trust policy is not allowed for the registered signer identity.",
                        )
                    )
            if trust_policy_ref in TRUST_POLICY_BY_ID:
                policy = TRUST_POLICY_BY_ID[trust_policy_ref]
                if signer_type not in set(policy["allowedSignerTypes"]):
                    reasons.append(
                        _reason(
                            "signer_type_mismatch",
                            "signer.signerType",
                            "Signer type is not allowed by the declared trust policy.",
                        )
                    )
                if signer.get("trustPolicyId") != trust_policy_ref:
                    reasons.append(
                        _reason(
                            "signer_policy_mismatch",
                            "signer.trustPolicyId",
                            "Signer trustPolicyId must match the claim trustPolicyRef.",
                        )
                    )
                if signer.get("signerRole") and signer["signerRole"] not in set(policy["requiredSignerRoles"]):
                    reasons.append(
                        _reason(
                            "unexpected_signer_role",
                            "signer.signerRole",
                            "Signer role is not allowed by the declared trust policy.",
                        )
                    )
                if actor.get("actorRole") and signer.get("signerRole") and actor["actorRole"] != signer["signerRole"]:
                    reasons.append(
                        _reason(
                            "actor_signer_role_mismatch",
                            "signer.signerRole",
                            "Actor and signer roles must match for self-attested evidence claims.",
                        )
                    )
                if policy["delegationRequired"]:
                    for field_name in ("delegatedBy", "delegationScope"):
                        if not signer.get(field_name):
                            reasons.append(
                                _reason(
                                    "missing_delegation",
                                    f"signer.{field_name}",
                                    "Delegated approver trust policies require explicit delegation metadata.",
                                )
                            )
                elif signer.get("delegatedBy") or signer.get("delegationScope"):
                    reasons.append(
                        _reason(
                            "unexpected_delegation",
                            "signer",
                            "Non-delegated trust policies must not carry delegatedBy or delegationScope metadata.",
                        )
                    )
            try:
                _parse_timestamp(signer["signedAt"])
            except (KeyError, ValueError):
                reasons.append(
                    _reason(
                        "invalid_signer_timestamp",
                        "signer.signedAt",
                        "Signer timestamps must be valid ISO 8601 date-time strings.",
                    )
                )

    if not raw.get("controlMappings"):
        reasons.append(
            _reason(
                "missing_control_mappings",
                "controlMappings",
                "Typed evidence claims must map to at least one framework target.",
            )
        )
    else:
        for index, mapping in enumerate(raw["controlMappings"]):
            if not mapping.get("controlId"):
                reasons.append(
                    _reason(
                        "missing_control_id",
                        f"controlMappings[{index}].controlId",
                        "Current OpenCompliance evidence claims require a concrete proxy controlId.",
                    )
                )

    return reasons


def validate_claims_path(path: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    raw_claims = json.loads(path.read_text())
    accepted: list[dict[str, Any]] = []
    rejected_claims: list[dict[str, Any]] = []

    for index, raw in enumerate(raw_claims):
        reasons = validate_claim(raw)
        if reasons:
            rejected_claims.append(
                {
                    "claimIndex": index,
                    "claimId": raw.get("claimId"),
                    "claimType": raw.get("claimType"),
                    "actorType": raw.get("actor", {}).get("actorType"),
                    "reasons": reasons,
                }
            )
        else:
            accepted.append(raw)

    rejection_artifact = {
        "artifactVersion": "0.1.0",
        "sourcePath": str(path),
        "acceptedClaimCount": len(accepted),
        "rejectedClaimCount": len(rejected_claims),
        "rejectedClaims": rejected_claims,
    }
    return accepted, rejection_artifact
