from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


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
    "network_firewall_boundary",
    "secure_configuration_state",
    "security_update_state",
    "malware_protection_state",
    "ai_content_labeling_state",
    "ai_content_provenance_state",
}

HUMAN_CLAIM_TYPES = {
    "access_review_closure_attestation",
    "ai_context_attestation",
    "ai_human_oversight_attestation",
    "ai_monitoring_attestation",
    "ai_risk_management_attestation",
    "ai_evaluation_attestation",
    "ai_data_quality_attestation",
    "configuration_exception_attestation",
    "incident_contact_matrix_attestation",
    "incident_response_runbook_attestation",
    "monitoring_review_attestation",
    "patch_exception_attestation",
    "training_attestation",
    "restore_test_attestation",
    "vendor_register_attestation",
    "vendor_security_terms_attestation",
    "dsr_runbook_attestation",
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

    if claim_type not in SYSTEM_CLAIM_TYPES | HUMAN_CLAIM_TYPES:
        reasons.append(
            _reason(
                "unknown_claim_type",
                "claimType",
                "Claim type is not in the current OpenCompliance synthetic corridor registry.",
            )
        )
        return reasons

    if claim_type in SYSTEM_CLAIM_TYPES and actor_type != "system":
        reasons.append(
            _reason(
                "actor_type_mismatch",
                "actor.actorType",
                "Machine evidence claim types must be produced by a system actor.",
            )
        )
    if claim_type in HUMAN_CLAIM_TYPES and actor_type != "human":
        reasons.append(
            _reason(
                "actor_type_mismatch",
                "actor.actorType",
                "Attestation claim types must be produced by a human actor.",
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
        for field_name in ("signerId", "signerType", "signatureType"):
            if not signer or not signer.get(field_name):
                reasons.append(
                    _reason(
                        "missing_signer",
                        f"signer.{field_name}",
                        "Human attestations must carry signer identity and signature metadata.",
                    )
                )
        if signer and signer.get("signerType") != "human":
            reasons.append(
                _reason(
                    "signer_type_mismatch",
                    "signer.signerType",
                    "Human attestations must be signed by a human signer in the current actor ontology.",
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
