from __future__ import annotations

from typing import Any


ACTOR_TYPES = frozenset(
    {
        "system",
        "human",
        "delegated_approver",
        "verifier_service",
        "independent_witness",
    }
)

EVIDENCE_CLAIM_ACTOR_TYPES = frozenset({"system", "human", "delegated_approver"})
ATTESTATION_ACTOR_TYPES = frozenset({"human", "delegated_approver"})
SIGNED_ACTOR_TYPES = frozenset({"human", "delegated_approver", "verifier_service", "independent_witness"})

SYSTEM_EXPORT_POLICY_ID = "oc.trust.system-export"
HUMAN_OWNER_ATTESTATION_POLICY_ID = "oc.trust.human-owner-attestation"
DELEGATED_SECURITY_APPROVER_POLICY_ID = "oc.trust.delegated-security-approver"
DELEGATED_PRIVACY_APPROVER_POLICY_ID = "oc.trust.delegated-privacy-approver"
DELEGATED_AI_GOVERNANCE_APPROVER_POLICY_ID = "oc.trust.delegated-ai-governance-approver"
VERIFIER_SERVICE_POLICY_ID = "oc.trust.verifier-service"
INDEPENDENT_WITNESS_POLICY_ID = "oc.trust.independent-witness"

OWNER_ATTESTATION_CLAIM_TYPES = frozenset(
    {
        "training_attestation",
        "restore_test_attestation",
    }
)

DELEGATED_SECURITY_APPROVER_CLAIM_TYPES = frozenset(
    {
        "change_review_attestation",
        "access_review_closure_attestation",
        "configuration_exception_attestation",
        "patch_exception_attestation",
        "incident_response_runbook_attestation",
        "incident_contact_matrix_attestation",
        "monitoring_review_attestation",
    }
)

DELEGATED_PRIVACY_APPROVER_CLAIM_TYPES = frozenset(
    {
        "vendor_register_attestation",
        "vendor_security_terms_attestation",
        "dsr_runbook_attestation",
    }
)

DELEGATED_AI_GOVERNANCE_APPROVER_CLAIM_TYPES = frozenset(
    {
        "ai_context_attestation",
        "ai_risk_management_attestation",
        "ai_human_oversight_attestation",
        "ai_monitoring_attestation",
        "ai_evaluation_attestation",
        "ai_data_quality_attestation",
    }
)

SYSTEM_EXPORT_SIGNER_ROLES = frozenset({"connector_service", "config_exporter", "monitoring_exporter"})
HUMAN_OWNER_SIGNER_ROLES = frozenset({"security_training_owner", "platform_recovery_owner"})
DELEGATED_SECURITY_SIGNER_ROLES = frozenset(
    {
        "identity_governance_delegate",
        "change_control_delegate",
        "platform_security_delegate",
        "operations_patch_delegate",
        "incident_response_delegate",
        "monitoring_delegate",
    }
)
DELEGATED_PRIVACY_SIGNER_ROLES = frozenset(
    {
        "privacy_delegate",
        "vendor_risk_delegate",
    }
)
DELEGATED_AI_GOVERNANCE_SIGNER_ROLES = frozenset(
    {
        "ai_governance_delegate",
        "ai_oversight_delegate",
        "ai_monitoring_delegate",
    }
)
VERIFIER_SERVICE_SIGNER_ROLES = frozenset({"release_signer", "verification_service"})
INDEPENDENT_WITNESS_SIGNER_ROLES = frozenset({"independent_replay_witness"})

TRUST_POLICIES: tuple[dict[str, Any], ...] = (
    {
        "policyId": SYSTEM_EXPORT_POLICY_ID,
        "surface": "evidence_claim",
        "description": "Deterministic system export collected by a scoped connector or exporter service.",
        "allowedActorTypes": ["system"],
        "allowedSignerTypes": [],
        "requiredSignerRoles": sorted(SYSTEM_EXPORT_SIGNER_ROLES),
        "delegationRequired": False,
    },
    {
        "policyId": HUMAN_OWNER_ATTESTATION_POLICY_ID,
        "surface": "evidence_claim",
        "description": "Direct human owner attestation with no delegated approval chain.",
        "allowedActorTypes": ["human"],
        "allowedSignerTypes": ["human"],
        "requiredSignerRoles": sorted(HUMAN_OWNER_SIGNER_ROLES),
        "delegationRequired": False,
    },
    {
        "policyId": DELEGATED_SECURITY_APPROVER_POLICY_ID,
        "surface": "evidence_claim",
        "description": "Delegated security approver attestation for operational exception, incident, and monitoring controls.",
        "allowedActorTypes": ["delegated_approver"],
        "allowedSignerTypes": ["delegated_approver"],
        "requiredSignerRoles": sorted(DELEGATED_SECURITY_SIGNER_ROLES),
        "delegationRequired": True,
    },
    {
        "policyId": DELEGATED_PRIVACY_APPROVER_POLICY_ID,
        "surface": "evidence_claim",
        "description": "Delegated privacy or vendor-risk approver attestation for privacy and supplier controls.",
        "allowedActorTypes": ["delegated_approver"],
        "allowedSignerTypes": ["delegated_approver"],
        "requiredSignerRoles": sorted(DELEGATED_PRIVACY_SIGNER_ROLES),
        "delegationRequired": True,
    },
    {
        "policyId": DELEGATED_AI_GOVERNANCE_APPROVER_POLICY_ID,
        "surface": "evidence_claim",
        "description": "Delegated AI governance approver attestation for documentary AI governance controls.",
        "allowedActorTypes": ["delegated_approver"],
        "allowedSignerTypes": ["delegated_approver"],
        "requiredSignerRoles": sorted(DELEGATED_AI_GOVERNANCE_SIGNER_ROLES),
        "delegationRequired": True,
    },
    {
        "policyId": VERIFIER_SERVICE_POLICY_ID,
        "surface": "signed_artifact",
        "description": "Verifier-side release or verification-service identity used to sign public artifact bundles.",
        "allowedActorTypes": ["verifier_service"],
        "allowedSignerTypes": ["verifier_service"],
        "requiredSignerRoles": sorted(VERIFIER_SERVICE_SIGNER_ROLES),
        "delegationRequired": False,
    },
    {
        "policyId": INDEPENDENT_WITNESS_POLICY_ID,
        "surface": "witness_receipt",
        "description": "Independent replay witness identity that issues receipts only after exact-match reruns.",
        "allowedActorTypes": ["independent_witness"],
        "allowedSignerTypes": ["independent_witness"],
        "requiredSignerRoles": sorted(INDEPENDENT_WITNESS_SIGNER_ROLES),
        "delegationRequired": False,
    },
)

TRUST_POLICY_BY_ID = {policy["policyId"]: policy for policy in TRUST_POLICIES}

ACTOR_IDENTITIES: tuple[dict[str, Any], ...] = (
    {
        "identityId": "ai-disclosure-exporter",
        "actorType": "system",
        "defaultActorRole": None,
        "defaultSignerRole": None,
        "trustPolicyIds": [SYSTEM_EXPORT_POLICY_ID],
        "surfaces": ["evidence_claim"],
        "synthetic": True,
        "notes": "Synthetic exporter for machine-checkable AI disclosure state.",
    },
    {
        "identityId": "ai-governance-lead@exampleco.test",
        "actorType": "delegated_approver",
        "defaultActorRole": "ai_governance_delegate",
        "defaultSignerRole": "ai_governance_delegate",
        "trustPolicyIds": [DELEGATED_AI_GOVERNANCE_APPROVER_POLICY_ID],
        "surfaces": ["evidence_claim"],
        "synthetic": True,
        "notes": "Synthetic delegated AI governance approver for ExampleCo.",
    },
    {
        "identityId": "ai-monitoring-owner@exampleco.test",
        "actorType": "delegated_approver",
        "defaultActorRole": "ai_monitoring_delegate",
        "defaultSignerRole": "ai_monitoring_delegate",
        "trustPolicyIds": [DELEGATED_AI_GOVERNANCE_APPROVER_POLICY_ID],
        "surfaces": ["evidence_claim"],
        "synthetic": True,
        "notes": "Synthetic delegated AI monitoring approver for ExampleCo.",
    },
    {
        "identityId": "ai-oversight-owner@exampleco.test",
        "actorType": "delegated_approver",
        "defaultActorRole": "ai_oversight_delegate",
        "defaultSignerRole": "ai_oversight_delegate",
        "trustPolicyIds": [DELEGATED_AI_GOVERNANCE_APPROVER_POLICY_ID],
        "surfaces": ["evidence_claim"],
        "synthetic": True,
        "notes": "Synthetic delegated AI oversight approver for ExampleCo.",
    },
    {
        "identityId": "ai-risk-owner@exampleco.test",
        "actorType": "delegated_approver",
        "defaultActorRole": "ai_governance_delegate",
        "defaultSignerRole": "ai_governance_delegate",
        "trustPolicyIds": [DELEGATED_AI_GOVERNANCE_APPROVER_POLICY_ID],
        "surfaces": ["evidence_claim"],
        "synthetic": True,
        "notes": "Synthetic delegated AI risk approver for ExampleCo.",
    },
    {
        "identityId": "architecture-exporter",
        "actorType": "system",
        "defaultActorRole": None,
        "defaultSignerRole": None,
        "trustPolicyIds": [SYSTEM_EXPORT_POLICY_ID],
        "surfaces": ["evidence_claim"],
        "synthetic": True,
        "notes": "Synthetic architecture export service for segmentation evidence.",
    },
    {
        "identityId": "asset-inventory-bot",
        "actorType": "system",
        "defaultActorRole": None,
        "defaultSignerRole": None,
        "trustPolicyIds": [SYSTEM_EXPORT_POLICY_ID],
        "surfaces": ["evidence_claim"],
        "synthetic": True,
        "notes": "Synthetic inventory bot for region and asset-state exports.",
    },
    {
        "identityId": "backup-config-exporter",
        "actorType": "system",
        "defaultActorRole": None,
        "defaultSignerRole": None,
        "trustPolicyIds": [SYSTEM_EXPORT_POLICY_ID],
        "surfaces": ["evidence_claim"],
        "synthetic": True,
        "notes": "Synthetic exporter for backup schedule state.",
    },
    {
        "identityId": "ci-policy-exporter",
        "actorType": "system",
        "defaultActorRole": None,
        "defaultSignerRole": None,
        "trustPolicyIds": [SYSTEM_EXPORT_POLICY_ID],
        "surfaces": ["evidence_claim"],
        "synthetic": True,
        "notes": "Synthetic CI policy export identity.",
    },
    {
        "identityId": "cloud-config-exporter",
        "actorType": "system",
        "defaultActorRole": None,
        "defaultSignerRole": None,
        "trustPolicyIds": [SYSTEM_EXPORT_POLICY_ID],
        "surfaces": ["evidence_claim"],
        "synthetic": True,
        "notes": "Synthetic cloud configuration export identity.",
    },
    {
        "identityId": "config-exporter",
        "actorType": "system",
        "defaultActorRole": None,
        "defaultSignerRole": None,
        "trustPolicyIds": [SYSTEM_EXPORT_POLICY_ID],
        "surfaces": ["evidence_claim"],
        "synthetic": True,
        "notes": "Synthetic secure-configuration export identity.",
    },
    {
        "identityId": "detection-engineering-owner@exampleco.test",
        "actorType": "delegated_approver",
        "defaultActorRole": "monitoring_delegate",
        "defaultSignerRole": "monitoring_delegate",
        "trustPolicyIds": [DELEGATED_SECURITY_APPROVER_POLICY_ID],
        "surfaces": ["evidence_claim"],
        "synthetic": True,
        "notes": "Synthetic delegated monitoring approver for ExampleCo.",
    },
    {
        "identityId": "edge-config-exporter",
        "actorType": "system",
        "defaultActorRole": None,
        "defaultSignerRole": None,
        "trustPolicyIds": [SYSTEM_EXPORT_POLICY_ID],
        "surfaces": ["evidence_claim"],
        "synthetic": True,
        "notes": "Synthetic edge and ingress configuration export identity.",
    },
    {
        "identityId": "iam-exporter",
        "actorType": "system",
        "defaultActorRole": None,
        "defaultSignerRole": None,
        "trustPolicyIds": [SYSTEM_EXPORT_POLICY_ID],
        "surfaces": ["evidence_claim"],
        "synthetic": True,
        "notes": "Synthetic IAM export identity.",
    },
    {
        "identityId": "identity-governance-owner@exampleco.test",
        "actorType": "delegated_approver",
        "defaultActorRole": "identity_governance_delegate",
        "defaultSignerRole": "identity_governance_delegate",
        "trustPolicyIds": [DELEGATED_SECURITY_APPROVER_POLICY_ID],
        "surfaces": ["evidence_claim"],
        "synthetic": True,
        "notes": "Synthetic delegated identity-governance approver for ExampleCo.",
    },
    {
        "identityId": "idp-review-exporter",
        "actorType": "system",
        "defaultActorRole": None,
        "defaultSignerRole": None,
        "trustPolicyIds": [SYSTEM_EXPORT_POLICY_ID],
        "surfaces": ["evidence_claim"],
        "synthetic": True,
        "notes": "Synthetic identity-review export identity.",
    },
    {
        "identityId": "idp-sync-bot",
        "actorType": "system",
        "defaultActorRole": None,
        "defaultSignerRole": None,
        "trustPolicyIds": [SYSTEM_EXPORT_POLICY_ID],
        "surfaces": ["evidence_claim"],
        "synthetic": True,
        "notes": "Synthetic identity-provider synchronization export identity.",
    },
    {
        "identityId": "malware-exporter",
        "actorType": "system",
        "defaultActorRole": None,
        "defaultSignerRole": None,
        "trustPolicyIds": [SYSTEM_EXPORT_POLICY_ID],
        "surfaces": ["evidence_claim"],
        "synthetic": True,
        "notes": "Synthetic malware-protection export identity.",
    },
    {
        "identityId": "monitoring-config-exporter",
        "actorType": "system",
        "defaultActorRole": None,
        "defaultSignerRole": None,
        "trustPolicyIds": [SYSTEM_EXPORT_POLICY_ID],
        "surfaces": ["evidence_claim"],
        "synthetic": True,
        "notes": "Synthetic monitoring-configuration export identity.",
    },
    {
        "identityId": "network-exporter",
        "actorType": "system",
        "defaultActorRole": None,
        "defaultSignerRole": None,
        "trustPolicyIds": [SYSTEM_EXPORT_POLICY_ID],
        "surfaces": ["evidence_claim"],
        "synthetic": True,
        "notes": "Synthetic network-boundary export identity.",
    },
    {
        "identityId": "oc-synthetic-independent-witness",
        "actorType": "independent_witness",
        "defaultActorRole": "independent_replay_witness",
        "defaultSignerRole": "independent_replay_witness",
        "trustPolicyIds": [INDEPENDENT_WITNESS_POLICY_ID],
        "surfaces": ["witness_receipt"],
        "synthetic": True,
        "notes": "Synthetic witness identity for fixture replay receipts.",
    },
    {
        "identityId": "oc-synthetic-release-witness",
        "actorType": "independent_witness",
        "defaultActorRole": "independent_replay_witness",
        "defaultSignerRole": "independent_replay_witness",
        "trustPolicyIds": [INDEPENDENT_WITNESS_POLICY_ID],
        "surfaces": ["release_attestation"],
        "synthetic": True,
        "notes": "Synthetic witness identity for release-bundle attestation.",
    },
    {
        "identityId": "oc-synthetic-signer",
        "actorType": "verifier_service",
        "defaultActorRole": "release_signer",
        "defaultSignerRole": "release_signer",
        "trustPolicyIds": [VERIFIER_SERVICE_POLICY_ID],
        "surfaces": ["signed_artifact"],
        "synthetic": True,
        "notes": "Synthetic verifier-service signing identity for public artifact bundles.",
    },
    {
        "identityId": "operations-owner@exampleco.test",
        "actorType": "delegated_approver",
        "defaultActorRole": "operations_patch_delegate",
        "defaultSignerRole": "operations_patch_delegate",
        "trustPolicyIds": [DELEGATED_SECURITY_APPROVER_POLICY_ID],
        "surfaces": ["evidence_claim"],
        "synthetic": True,
        "notes": "Synthetic delegated patch-operations approver for ExampleCo.",
    },
    {
        "identityId": "patch-exporter",
        "actorType": "system",
        "defaultActorRole": None,
        "defaultSignerRole": None,
        "trustPolicyIds": [SYSTEM_EXPORT_POLICY_ID],
        "surfaces": ["evidence_claim"],
        "synthetic": True,
        "notes": "Synthetic patch and update export identity.",
    },
    {
        "identityId": "platform-lead",
        "actorType": "human",
        "defaultActorRole": "platform_recovery_owner",
        "defaultSignerRole": "platform_recovery_owner",
        "trustPolicyIds": [HUMAN_OWNER_ATTESTATION_POLICY_ID],
        "surfaces": ["evidence_claim"],
        "synthetic": True,
        "notes": "Synthetic platform recovery owner for restore attestations.",
    },
    {
        "identityId": "platform-security-owner@exampleco.test",
        "actorType": "delegated_approver",
        "defaultActorRole": "platform_security_delegate",
        "defaultSignerRole": "platform_security_delegate",
        "trustPolicyIds": [DELEGATED_SECURITY_APPROVER_POLICY_ID],
        "surfaces": ["evidence_claim"],
        "synthetic": True,
        "notes": "Synthetic delegated platform-security approver for ExampleCo.",
    },
    {
        "identityId": "privacy-manager",
        "actorType": "delegated_approver",
        "defaultActorRole": "privacy_delegate",
        "defaultSignerRole": "privacy_delegate",
        "trustPolicyIds": [DELEGATED_PRIVACY_APPROVER_POLICY_ID],
        "surfaces": ["evidence_claim"],
        "synthetic": True,
        "notes": "Synthetic privacy approver for ExampleCo.",
    },
    {
        "identityId": "privacy-manager@exampleco.test",
        "actorType": "delegated_approver",
        "defaultActorRole": "vendor_risk_delegate",
        "defaultSignerRole": "vendor_risk_delegate",
        "trustPolicyIds": [DELEGATED_PRIVACY_APPROVER_POLICY_ID],
        "surfaces": ["evidence_claim"],
        "synthetic": True,
        "notes": "Synthetic vendor-risk approver for ExampleCo.",
    },
    {
        "identityId": "repo-policy-exporter",
        "actorType": "system",
        "defaultActorRole": None,
        "defaultSignerRole": None,
        "trustPolicyIds": [SYSTEM_EXPORT_POLICY_ID],
        "surfaces": ["evidence_claim"],
        "synthetic": True,
        "notes": "Synthetic repository-policy export identity.",
    },
    {
        "identityId": "security-manager",
        "actorType": "human",
        "defaultActorRole": "security_training_owner",
        "defaultSignerRole": "security_training_owner",
        "trustPolicyIds": [HUMAN_OWNER_ATTESTATION_POLICY_ID],
        "surfaces": ["evidence_claim"],
        "synthetic": True,
        "notes": "Synthetic security training owner for ExampleCo.",
    },
    {
        "identityId": "security-manager@exampleco.test",
        "actorType": "delegated_approver",
        "defaultActorRole": "change_control_delegate",
        "defaultSignerRole": "change_control_delegate",
        "trustPolicyIds": [DELEGATED_SECURITY_APPROVER_POLICY_ID],
        "surfaces": ["evidence_claim"],
        "synthetic": True,
        "notes": "Synthetic delegated change-control approver for ExampleCo.",
    },
    {
        "identityId": "security-operations-owner@exampleco.test",
        "actorType": "delegated_approver",
        "defaultActorRole": "incident_response_delegate",
        "defaultSignerRole": "incident_response_delegate",
        "trustPolicyIds": [DELEGATED_SECURITY_APPROVER_POLICY_ID],
        "surfaces": ["evidence_claim"],
        "synthetic": True,
        "notes": "Synthetic incident-response approver for ExampleCo.",
    },
    {
        "identityId": "storage-config-exporter",
        "actorType": "system",
        "defaultActorRole": None,
        "defaultSignerRole": None,
        "trustPolicyIds": [SYSTEM_EXPORT_POLICY_ID],
        "surfaces": ["evidence_claim"],
        "synthetic": True,
        "notes": "Synthetic storage-configuration export identity.",
    },
)

ACTOR_IDENTITY_BY_ID = {identity["identityId"]: identity for identity in ACTOR_IDENTITIES}

DEFAULT_ACTOR_ROLE_BY_CLAIM_TYPE = {
    "training_attestation": "security_training_owner",
    "restore_test_attestation": "platform_recovery_owner",
    "access_review_closure_attestation": "identity_governance_delegate",
    "change_review_attestation": "change_control_delegate",
    "configuration_exception_attestation": "platform_security_delegate",
    "patch_exception_attestation": "operations_patch_delegate",
    "incident_response_runbook_attestation": "incident_response_delegate",
    "incident_contact_matrix_attestation": "incident_response_delegate",
    "monitoring_review_attestation": "monitoring_delegate",
    "vendor_register_attestation": "privacy_delegate",
    "vendor_security_terms_attestation": "vendor_risk_delegate",
    "dsr_runbook_attestation": "privacy_delegate",
    "ai_context_attestation": "ai_governance_delegate",
    "ai_risk_management_attestation": "ai_governance_delegate",
    "ai_human_oversight_attestation": "ai_oversight_delegate",
    "ai_monitoring_attestation": "ai_monitoring_delegate",
    "ai_evaluation_attestation": "ai_governance_delegate",
    "ai_data_quality_attestation": "ai_governance_delegate",
}

DEFAULT_DELEGATED_BY_BY_POLICY = {
    DELEGATED_SECURITY_APPROVER_POLICY_ID: "head-of-security@exampleco.test",
    DELEGATED_PRIVACY_APPROVER_POLICY_ID: "head-of-privacy@exampleco.test",
    DELEGATED_AI_GOVERNANCE_APPROVER_POLICY_ID: "head-of-ai-governance@exampleco.test",
}

DEFAULT_DELEGATION_SCOPE_BY_CLAIM_TYPE = {
    "access_review_closure_attestation": "privileged_identity_review",
    "change_review_attestation": "change_governance",
    "configuration_exception_attestation": "configuration_exception_approval",
    "patch_exception_attestation": "patch_exception_approval",
    "incident_response_runbook_attestation": "incident_runbook_approval",
    "incident_contact_matrix_attestation": "incident_contact_maintenance",
    "monitoring_review_attestation": "telemetry_review_governance",
    "vendor_register_attestation": "privacy_supplier_governance",
    "vendor_security_terms_attestation": "high_risk_vendor_terms_review",
    "dsr_runbook_attestation": "privacy_runbook_approval",
    "ai_context_attestation": "ai_context_governance",
    "ai_risk_management_attestation": "ai_risk_governance",
    "ai_human_oversight_attestation": "ai_oversight_governance",
    "ai_monitoring_attestation": "ai_monitoring_governance",
    "ai_evaluation_attestation": "ai_evaluation_governance",
    "ai_data_quality_attestation": "ai_data_quality_governance",
}


def evidence_claim_policy_ids() -> set[str]:
    return {policy["policyId"] for policy in TRUST_POLICIES if policy["surface"] == "evidence_claim"}


def trust_policy_for_claim_type(claim_type: str) -> str:
    if claim_type in OWNER_ATTESTATION_CLAIM_TYPES:
        return HUMAN_OWNER_ATTESTATION_POLICY_ID
    if claim_type in DELEGATED_SECURITY_APPROVER_CLAIM_TYPES:
        return DELEGATED_SECURITY_APPROVER_POLICY_ID
    if claim_type in DELEGATED_PRIVACY_APPROVER_CLAIM_TYPES:
        return DELEGATED_PRIVACY_APPROVER_POLICY_ID
    if claim_type in DELEGATED_AI_GOVERNANCE_APPROVER_CLAIM_TYPES:
        return DELEGATED_AI_GOVERNANCE_APPROVER_POLICY_ID
    return SYSTEM_EXPORT_POLICY_ID


def allowed_attestation_actor(claim_type: str) -> bool:
    return trust_policy_for_claim_type(claim_type) != SYSTEM_EXPORT_POLICY_ID


def is_attestation_actor(actor_type: str) -> bool:
    return actor_type in ATTESTATION_ACTOR_TYPES


def default_actor_type_for_claim_type(claim_type: str) -> str:
    policy_id = trust_policy_for_claim_type(claim_type)
    if policy_id == HUMAN_OWNER_ATTESTATION_POLICY_ID:
        return "human"
    if policy_id in {
        DELEGATED_SECURITY_APPROVER_POLICY_ID,
        DELEGATED_PRIVACY_APPROVER_POLICY_ID,
        DELEGATED_AI_GOVERNANCE_APPROVER_POLICY_ID,
    }:
        return "delegated_approver"
    return "system"


def default_actor_role_for_claim_type(claim_type: str) -> str | None:
    return DEFAULT_ACTOR_ROLE_BY_CLAIM_TYPE.get(claim_type)


def default_delegated_by_for_claim_type(claim_type: str) -> str | None:
    return DEFAULT_DELEGATED_BY_BY_POLICY.get(trust_policy_for_claim_type(claim_type))


def default_delegation_scope_for_claim_type(claim_type: str) -> str | None:
    return DEFAULT_DELEGATION_SCOPE_BY_CLAIM_TYPE.get(claim_type)


def actor_identity(identity_id: str) -> dict[str, Any] | None:
    return ACTOR_IDENTITY_BY_ID.get(identity_id)
