from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

from ..actor_ontology import (
    SYSTEM_EXPORT_POLICY_ID,
    default_actor_role_for_claim_type,
    default_actor_type_for_claim_type,
    default_delegated_by_for_claim_type,
    default_delegation_scope_for_claim_type,
    trust_policy_for_claim_type,
)
from ..paths import find_repo_root


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text())


@lru_cache(maxsize=1)
def _control_boundaries_by_id(repo_root: str) -> dict[str, dict[str, Any]]:
    data = json.loads((Path(repo_root) / "open-specs" / "control-boundaries.json").read_text())
    return {control["controlId"]: control for control in data["controls"]}


def _control_mappings(fixture_root: Path, *control_refs: str) -> list[dict[str, str]]:
    boundaries_by_id = _control_boundaries_by_id(str(find_repo_root(fixture_root)))
    mappings: list[dict[str, str]] = []
    seen: set[tuple[str, str, str | None]] = set()
    for control_ref in control_refs:
        boundary = boundaries_by_id[control_ref]
        for mapping in boundary["sourceMappings"]:
            key = (
                mapping["framework"],
                mapping["family"],
                mapping.get("controlId"),
            )
            if key in seen:
                continue
            mappings.append(
                {
                    "framework": mapping["framework"],
                    "family": mapping["family"],
                    "controlId": mapping.get("controlId"),
                }
            )
            seen.add(key)
    return mappings


def _system_claim(
    claim_id: str,
    claim_type: str,
    source: dict[str, Any],
    control_mappings: list[dict[str, str]],
    payload_keys: list[str],
    provenance: dict[str, str],
) -> dict[str, Any]:
    actor: dict[str, Any] = {
        "actorId": source["actorId"],
        "actorType": source.get("actorType", "system"),
    }
    if source.get("actorRole"):
        actor["actorRole"] = source["actorRole"]
    return {
        "claimId": claim_id,
        "claimType": claim_type,
        "collectedAt": source["collectedAt"],
        "sourceSystem": source["sourceSystem"],
        "actor": actor,
        "trustPolicyRef": source.get("trustPolicyRef", SYSTEM_EXPORT_POLICY_ID),
        "controlMappings": control_mappings,
        "scope": {
            "environment": source["environment"],
            "assetGroup": source["assetGroup"],
        },
        "freshness": {
            "evaluatedAt": source["evaluatedAt"],
            "expiresAt": source["expiresAt"],
        },
        "payload": {key: source[key] for key in payload_keys},
        "provenance": provenance,
    }


def _human_claim(
    claim_id: str,
    claim_type: str,
    source: dict[str, Any],
    control_mappings: list[dict[str, str]],
    payload_keys: list[str],
    provenance: dict[str, str],
) -> dict[str, Any]:
    actor_type = source.get("actorType", default_actor_type_for_claim_type(claim_type))
    actor_role = source.get("actorRole", default_actor_role_for_claim_type(claim_type))
    actor: dict[str, Any] = {
        "actorId": source["actorId"],
        "actorType": actor_type,
    }
    if actor_role:
        actor["actorRole"] = actor_role
    trust_policy_ref = source.get("trustPolicyRef", trust_policy_for_claim_type(claim_type))
    signer: dict[str, Any] = {
        "signerId": source.get("signerId", source["actorId"]),
        "signerType": source.get("signerType", actor_type),
        "signatureType": source["signatureType"],
        "signedAt": source.get("signedAt", source["collectedAt"]),
        "trustPolicyId": source.get("signerTrustPolicyId", trust_policy_ref),
    }
    signer_role = source.get("signerRole", actor_role)
    if signer_role:
        signer["signerRole"] = signer_role
    delegated_by = source.get("delegatedBy", default_delegated_by_for_claim_type(claim_type))
    delegation_scope = source.get("delegationScope", default_delegation_scope_for_claim_type(claim_type))
    if delegated_by:
        signer["delegatedBy"] = delegated_by
    if delegation_scope:
        signer["delegationScope"] = delegation_scope
    return {
        "claimId": claim_id,
        "claimType": claim_type,
        "collectedAt": source["collectedAt"],
        "sourceSystem": source["sourceSystem"],
        "actor": actor,
        "trustPolicyRef": trust_policy_ref,
        "controlMappings": control_mappings,
        "scope": {
            "environment": source["environment"],
            "assetGroup": source["assetGroup"],
        },
        "freshness": {
            "evaluatedAt": source["evaluatedAt"],
            "expiresAt": source["expiresAt"],
        },
        "payload": {key: source[key] for key in payload_keys},
        "signer": signer,
        "provenance": provenance,
    }


def build_fixture_claims(fixture_root: Path) -> list[dict[str, Any]]:
    fixture = fixture_root.name
    source_root = fixture_root / "source-exports"
    if fixture == "minimal":
        return [
            _system_claim(
                "EV-001",
                "identity_mfa_enforcement",
                _load_json(source_root / "idp-admin-mfa.json"),
                [
                    {
                        "framework": "SOC 2",
                        "family": "access_control",
                        "controlId": "soc2.family.access_control",
                    },
                    {
                        "framework": "ISO 27001",
                        "family": "identity_and_access_management",
                        "controlId": "iso27001.family.identity_and_access_management",
                    },
                ],
                ["mfaRequired", "conditionalAccessEnabled"],
                {
                    "exportId": "exampleco-minimal-idp-export-001",
                    "collectionMethod": "scheduled_api_export",
                    "sourcePath": "/synthetic/idp/admins/mfa",
                    "digestAlgorithm": "sha256",
                },
            ),
            _system_claim(
                "EV-002",
                "audit_logging_state",
                _load_json(source_root / "cloud-logging.json"),
                [
                    {
                        "framework": "SOC 2",
                        "family": "logging_monitoring",
                        "controlId": "soc2.family.logging_monitoring",
                    },
                    {
                        "framework": "ISO 27001",
                        "family": "logging_and_monitoring",
                        "controlId": "iso27001.family.logging_and_monitoring",
                    },
                ],
                ["auditLoggingEnabled", "retentionDays"],
                {
                    "exportId": "exampleco-minimal-cloud-export-001",
                    "collectionMethod": "scheduled_api_export",
                    "sourcePath": "/synthetic/cloud/logging",
                    "digestAlgorithm": "sha256",
                },
            ),
            _human_claim(
                "EV-003",
                "training_attestation",
                _load_json(source_root / "training-attestation.json"),
                [
                    {
                        "framework": "ISO 27001",
                        "family": "awareness_and_training",
                        "controlId": "iso27001.family.awareness_and_training",
                    }
                ],
                ["trainingComplete", "completionWindowDays", "attestedPopulation"],
                {
                    "exportId": "exampleco-minimal-training-attestation-001",
                    "collectionMethod": "signed_attestation",
                    "sourcePath": "/synthetic/hris/training",
                    "digestAlgorithm": "sha256",
                },
            ),
        ]
    if fixture == "failed":
        return [
            _system_claim(
                "EV-301",
                "identity_mfa_enforcement",
                _load_json(source_root / "idp-admin-mfa.json"),
                [
                    {
                        "framework": "SOC 2",
                        "family": "access_control",
                        "controlId": "soc2.family.access_control",
                    },
                    {
                        "framework": "ISO 27001",
                        "family": "identity_and_access_management",
                        "controlId": "iso27001.family.identity_and_access_management",
                    },
                ],
                ["mfaRequired", "conditionalAccessEnabled"],
                {
                    "exportId": "exampleco-failed-idp-export-001",
                    "collectionMethod": "scheduled_api_export",
                    "sourcePath": "/synthetic/idp/admins/mfa",
                    "digestAlgorithm": "sha256",
                },
            ),
            _system_claim(
                "EV-302",
                "audit_logging_state",
                _load_json(source_root / "cloud-logging.json"),
                [
                    {
                        "framework": "SOC 2",
                        "family": "logging_monitoring",
                        "controlId": "soc2.family.logging_monitoring",
                    },
                    {
                        "framework": "ISO 27001",
                        "family": "logging_and_monitoring",
                        "controlId": "iso27001.family.logging_and_monitoring",
                    },
                ],
                ["auditLoggingEnabled", "retentionDays"],
                {
                    "exportId": "exampleco-failed-cloud-export-001",
                    "collectionMethod": "scheduled_api_export",
                    "sourcePath": "/synthetic/cloud/logging",
                    "digestAlgorithm": "sha256",
                },
            ),
            _human_claim(
                "EV-303",
                "training_attestation",
                _load_json(source_root / "training-attestation.json"),
                [
                    {
                        "framework": "ISO 27001",
                        "family": "awareness_and_training",
                        "controlId": "iso27001.family.awareness_and_training",
                    }
                ],
                ["trainingComplete", "completionWindowDays", "attestedPopulation"],
                {
                    "exportId": "exampleco-failed-training-attestation-001",
                    "collectionMethod": "signed_attestation",
                    "sourcePath": "/synthetic/hris/training",
                    "digestAlgorithm": "sha256",
                },
            ),
        ]
    if fixture == "medium":
        return [
            _system_claim(
                "EV-101",
                "identity_mfa_enforcement",
                _load_json(source_root / "idp-admin-mfa.json"),
                [
                    {
                        "framework": "SOC 2",
                        "family": "access_control",
                        "controlId": "soc2.family.access_control",
                    },
                    {
                        "framework": "ISO 27001",
                        "family": "identity_and_access_management",
                        "controlId": "iso27001.family.identity_and_access_management",
                    },
                    {
                        "framework": "IRAP",
                        "family": "identity_access",
                        "controlId": "irap.family.identity_access",
                    },
                    {
                        "framework": "GDPR",
                        "family": "security_of_processing",
                        "controlId": "gdpr.family.security_of_processing",
                    },
                ],
                ["mfaRequired", "conditionalAccessEnabled"],
                {
                    "exportId": "export-exampleco-idp-2026-03-24-a",
                    "collectionMethod": "synthetic_export",
                    "sourcePath": "exports/idp/admin-identities.json",
                    "digestAlgorithm": "sha256",
                },
            ),
            _system_claim(
                "EV-128",
                "infrastructure_auth_uniqueness_state",
                _load_json(source_root / "idp-admin-mfa.json"),
                _control_mappings(fixture_root, "oc.id-04"),
                ["namedAccountsRequired", "sharedAccountsPresent"],
                {
                    "exportId": "export-exampleco-idp-2026-03-24-b",
                    "collectionMethod": "synthetic_export",
                    "sourcePath": "exports/idp/admin-identities.json",
                    "digestAlgorithm": "sha256",
                },
            ),
            _system_claim(
                "EV-130",
                "password_policy_state",
                _load_json(source_root / "idp-admin-mfa.json"),
                _control_mappings(fixture_root, "oc.id-05"),
                [
                    "minimumLengthAtLeast12",
                    "noMaximumLengthRestriction",
                    "commonPasswordBlockingEnabled",
                ],
                {
                    "exportId": "export-exampleco-idp-2026-03-24-c",
                    "collectionMethod": "synthetic_export",
                    "sourcePath": "exports/idp/password-policy.json",
                    "digestAlgorithm": "sha256",
                },
            ),
            _system_claim(
                "EV-131",
                "web_application_firewall_state",
                _load_json(source_root / "edge-waf.json"),
                _control_mappings(fixture_root, "oc.web-01"),
                [
                    "wafAttachedToPublicIngress",
                    "blockingModeEnabled",
                    "managedRuleSetActive",
                ],
                {
                    "exportId": "export-exampleco-edge-2026-03-24-b",
                    "collectionMethod": "synthetic_export",
                    "sourcePath": "exports/edge/waf.json",
                    "digestAlgorithm": "sha256",
                },
            ),
            _system_claim(
                "EV-129",
                "environment_segmentation_state",
                _load_json(source_root / "environment-segmentation.json"),
                _control_mappings(fixture_root, "oc.seg-01"),
                [
                    "customerBoundaryEnforced",
                    "productionSeparatedFromNonProduction",
                    "undeclaredCrossEnvironmentPathsPresent",
                ],
                {
                    "exportId": "export-exampleco-architecture-2026-03-24-a",
                    "collectionMethod": "synthetic_export",
                    "sourcePath": "exports/architecture/environment-segmentation.json",
                    "digestAlgorithm": "sha256",
                },
            ),
            _system_claim(
                "EV-102",
                "audit_logging_state",
                _load_json(source_root / "cloud-logging.json"),
                [
                    {
                        "framework": "SOC 2",
                        "family": "logging_monitoring",
                        "controlId": "soc2.family.logging_monitoring",
                    },
                    {
                        "framework": "ISO 27001",
                        "family": "logging_and_monitoring",
                        "controlId": "iso27001.family.logging_and_monitoring",
                    },
                    {
                        "framework": "IRAP",
                        "family": "logging_monitoring",
                        "controlId": "irap.family.logging_monitoring",
                    },
                ],
                ["auditLoggingEnabled", "retentionDays"],
                {
                    "exportId": "export-exampleco-cloud-2026-03-24-a",
                    "collectionMethod": "synthetic_export",
                    "sourcePath": "exports/cloud/audit-logging.json",
                    "digestAlgorithm": "sha256",
                },
            ),
            _system_claim(
                "EV-132",
                "central_monitoring_state",
                _load_json(source_root / "central-monitoring.json"),
                _control_mappings(fixture_root, "oc.mon-01"),
                ["centralSinkConfigured", "scopedAssetsForwarded", "alertRulesEnabled"],
                {
                    "exportId": "export-exampleco-monitoring-2026-03-24-a",
                    "collectionMethod": "synthetic_export",
                    "sourcePath": "exports/monitoring/central-sink.json",
                    "digestAlgorithm": "sha256",
                },
            ),
            _system_claim(
                "EV-103",
                "tls_ingress_configuration",
                _load_json(source_root / "edge-tls.json"),
                _control_mappings(fixture_root, "oc.net-01", "oc.net-04"),
                ["httpsOnly", "minTlsVersion", "managedCertificatesActive", "plaintextDisabled"],
                {
                    "exportId": "export-exampleco-edge-2026-03-24-a",
                    "collectionMethod": "synthetic_export",
                    "sourcePath": "exports/edge/tls.json",
                    "digestAlgorithm": "sha256",
                },
            ),
            _system_claim(
                "EV-127",
                "encryption_at_rest_state",
                _load_json(source_root / "storage-encryption.json"),
                _control_mappings(fixture_root, "oc.crypt-01"),
                ["encryptionEnabled", "customerDataStoresCovered", "unencryptedStoresPresent"],
                {
                    "exportId": "export-exampleco-storage-2026-03-24-a",
                    "collectionMethod": "synthetic_export",
                    "sourcePath": "exports/storage/encryption-at-rest.json",
                    "digestAlgorithm": "sha256",
                },
            ),
            _system_claim(
                "EV-120",
                "network_firewall_boundary",
                _load_json(source_root / "network-firewall.json"),
                _control_mappings(fixture_root, "oc.net-02", "oc.net-03"),
                [
                    "defaultDenyInbound",
                    "declaredIngressPorts",
                    "undeclaredIngressPresent",
                    "boundaryAttachedToIngressPath",
                    "adminIngressRestricted",
                    "approvedAdminSourceRanges",
                    "unapprovedAdminIngressPresent",
                ],
                {
                    "exportId": "export-exampleco-network-2026-03-24-a",
                    "collectionMethod": "synthetic_export",
                    "sourcePath": "exports/network/firewall-boundary.json",
                    "digestAlgorithm": "sha256",
                },
            ),
            _system_claim(
                "EV-104",
                "service_account_key_hygiene",
                _load_json(source_root / "service-account-keys.json"),
                [
                    {
                        "framework": "SOC 2",
                        "family": "key_management",
                        "controlId": "soc2.family.key_management",
                    },
                    {
                        "framework": "ISO 27001",
                        "family": "cryptographic_key_management",
                        "controlId": "iso27001.family.cryptographic_key_management",
                    },
                    {
                        "framework": "IRAP",
                        "family": "secrets_and_machine_credentials",
                        "controlId": "irap.family.secrets_and_machine_credentials",
                    },
                    {
                        "framework": "GDPR",
                        "family": "security_of_processing",
                        "controlId": "gdpr.family.security_of_processing",
                    },
                ],
                ["userManagedKeysPresent", "maxUserManagedKeyAgeDays"],
                {
                    "exportId": "export-exampleco-iam-2026-03-24-a",
                    "collectionMethod": "synthetic_export",
                    "sourcePath": "exports/iam/service-account-keys.json",
                    "digestAlgorithm": "sha256",
                },
            ),
            _system_claim(
                "EV-105",
                "approved_region_deployment",
                _load_json(source_root / "approved-regions.json"),
                [
                    {
                        "framework": "IRAP",
                        "family": "hosting_and_data_location",
                        "controlId": "irap.family.hosting_and_data_location",
                    },
                    {
                        "framework": "GDPR",
                        "family": "data_locality_and_transfer_boundary",
                        "controlId": "gdpr.family.data_locality_and_transfer_boundary",
                    },
                ],
                ["approvedRegions", "observedRegions", "undeclaredRegionsPresent"],
                {
                    "exportId": "export-exampleco-assets-2026-03-24-a",
                    "collectionMethod": "synthetic_export",
                    "sourcePath": "exports/assets/regions.json",
                    "digestAlgorithm": "sha256",
                },
            ),
            _system_claim(
                "EV-106",
                "backup_snapshot_schedule",
                _load_json(source_root / "backup-schedule.json"),
                [
                    {
                        "framework": "SOC 2",
                        "family": "backup_and_recovery",
                        "controlId": "soc2.family.backup_and_recovery",
                    },
                    {
                        "framework": "ISO 27001",
                        "family": "backup_and_recovery",
                        "controlId": "iso27001.family.backup_and_recovery",
                    },
                    {
                        "framework": "IRAP",
                        "family": "backup_and_recovery",
                        "controlId": "irap.family.backup_and_recovery",
                    },
                ],
                ["snapshotsEnabled", "snapshotFrequencyHours", "immutableWindowDays"],
                {
                    "exportId": "export-exampleco-backups-2026-03-24-a",
                    "collectionMethod": "synthetic_export",
                    "sourcePath": "exports/backups/snapshot-schedule.json",
                    "digestAlgorithm": "sha256",
                },
            ),
            _human_claim(
                "EV-107",
                "training_attestation",
                _load_json(source_root / "training-attestation.json"),
                [
                    {
                        "framework": "SOC 2",
                        "family": "security_awareness",
                        "controlId": "soc2.family.security_awareness",
                    },
                    {
                        "framework": "ISO 27001",
                        "family": "awareness_and_training",
                        "controlId": "iso27001.family.awareness_and_training",
                    },
                ],
                ["trainingComplete", "completionWindowDays", "attestedPopulation"],
                {
                    "exportId": "attestation-exampleco-training-2026-q1",
                    "collectionMethod": "synthetic_attestation",
                    "sourcePath": "attestations/training-q1.json",
                    "digestAlgorithm": "sha256",
                },
            ),
            _human_claim(
                "EV-108",
                "restore_test_attestation",
                _load_json(source_root / "restore-attestation.json"),
                [
                    {
                        "framework": "SOC 2",
                        "family": "backup_and_recovery",
                        "controlId": "soc2.family.backup_and_recovery",
                    },
                    {
                        "framework": "ISO 27001",
                        "family": "backup_and_recovery",
                        "controlId": "iso27001.family.backup_and_recovery",
                    },
                    {
                        "framework": "IRAP",
                        "family": "backup_and_recovery",
                        "controlId": "irap.family.backup_and_recovery",
                    },
                ],
                ["restoreTestCompleted", "testWindowDays", "scenarioId"],
                {
                    "exportId": "attestation-exampleco-restore-q1",
                    "collectionMethod": "synthetic_attestation",
                    "sourcePath": "attestations/restore-drill-q1.json",
                    "digestAlgorithm": "sha256",
                },
            ),
            _human_claim(
                "EV-109",
                "vendor_register_attestation",
                _load_json(source_root / "vendor-register-attestation.json"),
                [
                    {
                        "framework": "SOC 2",
                        "family": "vendor_management",
                        "controlId": "soc2.family.vendor_management",
                    },
                    {
                        "framework": "ISO 27001",
                        "family": "supplier_relationships",
                        "controlId": "iso27001.family.supplier_relationships",
                    },
                    {
                        "framework": "GDPR",
                        "family": "processors_and_subprocessors",
                        "controlId": "gdpr.family.processors_and_subprocessors",
                    },
                ],
                ["registerCurrent", "dpaCoverageDeclared", "reviewedSubprocessors"],
                {
                    "exportId": "attestation-exampleco-vendors-2026-q1",
                    "collectionMethod": "synthetic_attestation",
                    "sourcePath": "attestations/vendor-register-q1.json",
                    "digestAlgorithm": "sha256",
                },
            ),
            _human_claim(
                "EV-110",
                "dsr_runbook_attestation",
                _load_json(source_root / "dsr-runbook-attestation.json"),
                [
                    {
                        "framework": "GDPR",
                        "family": "data_subject_rights",
                        "controlId": "gdpr.family.data_subject_rights",
                    },
                ],
                ["runbookApproved", "ownerRole", "reviewWindowDays"],
                {
                    "exportId": "attestation-exampleco-dsr-2026-q1",
                    "collectionMethod": "synthetic_attestation",
                    "sourcePath": "attestations/dsr-runbook-q1.json",
                    "digestAlgorithm": "sha256",
                },
            ),
            _system_claim(
                "EV-111",
                "repo_branch_protection",
                _load_json(source_root / "repo-branch-protection.json"),
                [
                    {
                        "framework": "SOC 2",
                        "family": "change_management",
                        "controlId": "soc2.family.change_management",
                    },
                    {
                        "framework": "ISO 27001",
                        "family": "secure_development_and_change_control",
                        "controlId": "iso27001.family.secure_development_and_change_control",
                    },
                    {
                        "framework": "IRAP",
                        "family": "secure_development_and_change",
                        "controlId": "irap.family.secure_development_and_change",
                    },
                ],
                [
                    "defaultBranchProtected",
                    "requiredApprovals",
                    "statusChecksRequired",
                    "forcePushesBlocked",
                    "adminBypassRestricted",
                ],
                {
                    "exportId": "export-exampleco-repo-2026-03-24-a",
                    "collectionMethod": "synthetic_export",
                    "sourcePath": "exports/repo/branch-protection.json",
                    "digestAlgorithm": "sha256",
                },
            ),
            _system_claim(
                "EV-112",
                "ci_workflow_policy",
                _load_json(source_root / "ci-workflow-policy.json"),
                [
                    {
                        "framework": "SOC 2",
                        "family": "change_management",
                        "controlId": "soc2.family.change_management",
                    },
                    {
                        "framework": "ISO 27001",
                        "family": "secure_development_and_change_control",
                        "controlId": "iso27001.family.secure_development_and_change_control",
                    },
                    {
                        "framework": "IRAP",
                        "family": "secure_development_and_change",
                        "controlId": "irap.family.secure_development_and_change",
                    },
                ],
                [
                    "workflowReviewRequired",
                    "trustedPublishingOnly",
                    "protectedRefsOnly",
                    "environmentApprovalsRequired",
                ],
                {
                    "exportId": "export-exampleco-ci-2026-03-24-a",
                    "collectionMethod": "synthetic_export",
                    "sourcePath": "exports/ci/workflow-policy.json",
                    "digestAlgorithm": "sha256",
                },
            ),
            _human_claim(
                "EV-113",
                "change_review_attestation",
                _load_json(source_root / "change-review-attestation.json"),
                [
                    {
                        "framework": "SOC 2",
                        "family": "change_management",
                        "controlId": "soc2.family.change_management",
                    },
                    {
                        "framework": "ISO 27001",
                        "family": "secure_development_and_change_control",
                        "controlId": "iso27001.family.secure_development_and_change_control",
                    },
                    {
                        "framework": "IRAP",
                        "family": "secure_development_and_change",
                        "controlId": "irap.family.secure_development_and_change",
                    },
                ],
                ["changeReviewPolicyApproved", "emergencyChangeProcessDeclared", "reviewWindowDays"],
                {
                    "exportId": "attestation-exampleco-change-review-2026-q1",
                    "collectionMethod": "synthetic_attestation",
                    "sourcePath": "attestations/change-review-q1.json",
                    "digestAlgorithm": "sha256",
                },
            ),
            _human_claim(
                "EV-114",
                "access_review_closure_attestation",
                _load_json(source_root / "access-review-closure-attestation.json"),
                _control_mappings(fixture_root, "oc.id-03"),
                ["reviewCompleted", "reviewWindowDays", "reviewPopulation", "highRiskFindingsOpen"],
                {
                    "exportId": "attestation-exampleco-access-review-closure-2026-q1",
                    "collectionMethod": "synthetic_attestation",
                    "sourcePath": "attestations/access-review-closure-q1.json",
                    "digestAlgorithm": "sha256",
                },
            ),
            _human_claim(
                "EV-115",
                "configuration_exception_attestation",
                _load_json(source_root / "configuration-exception-attestation.json"),
                _control_mappings(fixture_root, "oc.cfg-02"),
                ["exceptionRegisterCurrent", "expiredExceptionsCount", "reviewWindowDays"],
                {
                    "exportId": "attestation-exampleco-configuration-exceptions-2026-q1",
                    "collectionMethod": "synthetic_attestation",
                    "sourcePath": "attestations/configuration-exceptions-q1.json",
                    "digestAlgorithm": "sha256",
                },
            ),
            _human_claim(
                "EV-116",
                "patch_exception_attestation",
                _load_json(source_root / "patch-exception-attestation.json"),
                _control_mappings(fixture_root, "oc.patch-02"),
                ["exceptionRegisterCurrent", "compensatingControlsDeclared", "expiredExceptionsCount", "reviewWindowDays"],
                {
                    "exportId": "attestation-exampleco-patch-exceptions-2026-q1",
                    "collectionMethod": "synthetic_attestation",
                    "sourcePath": "attestations/patch-exceptions-q1.json",
                    "digestAlgorithm": "sha256",
                },
            ),
            _human_claim(
                "EV-117",
                "incident_response_runbook_attestation",
                _load_json(source_root / "incident-runbook-attestation.json"),
                _control_mappings(fixture_root, "oc.ir-01"),
                ["runbookApproved", "ownerRole", "reviewWindowDays"],
                {
                    "exportId": "attestation-exampleco-incident-runbook-2026-q1",
                    "collectionMethod": "synthetic_attestation",
                    "sourcePath": "attestations/incident-runbook-q1.json",
                    "digestAlgorithm": "sha256",
                },
            ),
            _human_claim(
                "EV-118",
                "incident_contact_matrix_attestation",
                _load_json(source_root / "incident-contact-matrix-attestation.json"),
                _control_mappings(fixture_root, "oc.ir-02"),
                ["contactsCurrent", "escalationPathDocumented", "reviewWindowDays"],
                {
                    "exportId": "attestation-exampleco-incident-contacts-2026-q1",
                    "collectionMethod": "synthetic_attestation",
                    "sourcePath": "attestations/incident-contact-matrix-q1.json",
                    "digestAlgorithm": "sha256",
                },
            ),
            _human_claim(
                "EV-119",
                "vendor_security_terms_attestation",
                _load_json(source_root / "vendor-security-terms-attestation.json"),
                _control_mappings(fixture_root, "oc.vendor-02"),
                ["requiredSecurityTermsPresent", "privacyTermsPresent", "highRiskVendorsCovered", "reviewWindowDays"],
                {
                    "exportId": "attestation-exampleco-vendor-terms-2026-q1",
                    "collectionMethod": "synthetic_attestation",
                    "sourcePath": "attestations/vendor-security-terms-q1.json",
                    "digestAlgorithm": "sha256",
                },
            ),
            _human_claim(
                "EV-133",
                "monitoring_review_attestation",
                _load_json(source_root / "monitoring-review-attestation.json"),
                _control_mappings(fixture_root, "oc.mon-02"),
                [
                    "alertReviewCadenceDeclared",
                    "monitoringOwnerRole",
                    "retentionOperationsCovered",
                    "reviewWindowDays",
                ],
                {
                    "exportId": "attestation-exampleco-monitoring-review-2026-q1",
                    "collectionMethod": "synthetic_attestation",
                    "sourcePath": "attestations/monitoring-review-q1.json",
                    "digestAlgorithm": "sha256",
                },
            ),
        ]
    if fixture == "stale":
        return [
            _system_claim(
                "EV-401",
                "identity_mfa_enforcement",
                _load_json(source_root / "idp-admin-mfa.json"),
                [
                    {
                        "framework": "SOC 2",
                        "family": "access_control",
                        "controlId": "soc2.family.access_control",
                    },
                    {
                        "framework": "ISO 27001",
                        "family": "identity_and_access_management",
                        "controlId": "iso27001.family.identity_and_access_management",
                    },
                ],
                ["mfaRequired", "conditionalAccessEnabled"],
                {
                    "exportId": "exampleco-stale-idp-export-001",
                    "collectionMethod": "scheduled_api_export",
                    "sourcePath": "/synthetic/idp/admins/mfa",
                    "digestAlgorithm": "sha256",
                },
            ),
            _system_claim(
                "EV-402",
                "audit_logging_state",
                _load_json(source_root / "cloud-logging.json"),
                [
                    {
                        "framework": "SOC 2",
                        "family": "logging_monitoring",
                        "controlId": "soc2.family.logging_monitoring",
                    },
                    {
                        "framework": "ISO 27001",
                        "family": "logging_and_monitoring",
                        "controlId": "iso27001.family.logging_and_monitoring",
                    },
                ],
                ["auditLoggingEnabled", "retentionDays"],
                {
                    "exportId": "exampleco-stale-cloud-export-001",
                    "collectionMethod": "scheduled_api_export",
                    "sourcePath": "/synthetic/cloud/logging",
                    "digestAlgorithm": "sha256",
                },
            ),
            _human_claim(
                "EV-403",
                "training_attestation",
                _load_json(source_root / "training-attestation.json"),
                [
                    {
                        "framework": "ISO 27001",
                        "family": "awareness_and_training",
                        "controlId": "iso27001.family.awareness_and_training",
                    }
                ],
                ["trainingComplete", "completionWindowDays", "attestedPopulation"],
                {
                    "exportId": "exampleco-stale-training-attestation-001",
                    "collectionMethod": "signed_attestation",
                    "sourcePath": "/synthetic/hris/training",
                    "digestAlgorithm": "sha256",
                },
            ),
            _human_claim(
                "EV-404",
                "restore_test_attestation",
                _load_json(source_root / "restore-attestation.json"),
                [
                    {
                        "framework": "SOC 2",
                        "family": "backup_and_recovery",
                        "controlId": "soc2.family.backup_and_recovery",
                    },
                    {
                        "framework": "ISO 27001",
                        "family": "backup_and_recovery",
                        "controlId": "iso27001.family.backup_and_recovery",
                    },
                ],
                ["restoreTestCompleted", "testWindowDays", "scenarioId"],
                {
                    "exportId": "exampleco-stale-restore-attestation-001",
                    "collectionMethod": "signed_attestation",
                    "sourcePath": "/synthetic/dr/restore-tests",
                    "digestAlgorithm": "sha256",
                },
            ),
        ]
    if fixture == "issued":
        return [
            _system_claim(
                "EV-201",
                "identity_mfa_enforcement",
                _load_json(source_root / "idp-admin-mfa.json"),
                [
                    {
                        "framework": "SOC 2",
                        "family": "access_control",
                        "controlId": "soc2.family.access_control",
                    },
                    {
                        "framework": "ISO 27001",
                        "family": "identity_and_access_management",
                        "controlId": "iso27001.family.identity_and_access_management",
                    },
                ],
                ["mfaRequired", "conditionalAccessEnabled"],
                {
                    "exportId": "exampleco-issued-idp-export-001",
                    "collectionMethod": "scheduled_api_export",
                    "sourcePath": "/synthetic/idp/admins/mfa",
                    "digestAlgorithm": "sha256",
                },
            ),
            _system_claim(
                "EV-209",
                "infrastructure_auth_uniqueness_state",
                _load_json(source_root / "idp-admin-mfa.json"),
                _control_mappings(fixture_root, "oc.id-04"),
                ["namedAccountsRequired", "sharedAccountsPresent"],
                {
                    "exportId": "exampleco-issued-idp-export-002",
                    "collectionMethod": "scheduled_api_export",
                    "sourcePath": "/synthetic/idp/admins/mfa",
                    "digestAlgorithm": "sha256",
                },
            ),
            _system_claim(
                "EV-211",
                "password_policy_state",
                _load_json(source_root / "idp-admin-mfa.json"),
                _control_mappings(fixture_root, "oc.id-05"),
                [
                    "minimumLengthAtLeast12",
                    "noMaximumLengthRestriction",
                    "commonPasswordBlockingEnabled",
                ],
                {
                    "exportId": "exampleco-issued-idp-export-003",
                    "collectionMethod": "scheduled_api_export",
                    "sourcePath": "/synthetic/idp/password-policy",
                    "digestAlgorithm": "sha256",
                },
            ),
            _system_claim(
                "EV-212",
                "web_application_firewall_state",
                _load_json(source_root / "edge-waf.json"),
                _control_mappings(fixture_root, "oc.web-01"),
                [
                    "wafAttachedToPublicIngress",
                    "blockingModeEnabled",
                    "managedRuleSetActive",
                ],
                {
                    "exportId": "exampleco-issued-edge-export-001",
                    "collectionMethod": "synthetic_export",
                    "sourcePath": "exports/edge/waf.json",
                    "digestAlgorithm": "sha256",
                },
            ),
            _system_claim(
                "EV-210",
                "environment_segmentation_state",
                _load_json(source_root / "environment-segmentation.json"),
                _control_mappings(fixture_root, "oc.seg-01"),
                [
                    "customerBoundaryEnforced",
                    "productionSeparatedFromNonProduction",
                    "undeclaredCrossEnvironmentPathsPresent",
                ],
                {
                    "exportId": "exampleco-issued-architecture-export-001",
                    "collectionMethod": "scheduled_api_export",
                    "sourcePath": "/synthetic/architecture/environment-segmentation",
                    "digestAlgorithm": "sha256",
                },
            ),
            _system_claim(
                "EV-202",
                "audit_logging_state",
                _load_json(source_root / "cloud-logging.json"),
                [
                    {
                        "framework": "SOC 2",
                        "family": "logging_monitoring",
                        "controlId": "soc2.family.logging_monitoring",
                    },
                    {
                        "framework": "ISO 27001",
                        "family": "logging_and_monitoring",
                        "controlId": "iso27001.family.logging_and_monitoring",
                    },
                ],
                ["auditLoggingEnabled", "retentionDays"],
                {
                    "exportId": "exampleco-issued-cloud-export-001",
                    "collectionMethod": "scheduled_api_export",
                    "sourcePath": "/synthetic/cloud/logging",
                    "digestAlgorithm": "sha256",
                },
            ),
            _system_claim(
                "EV-213",
                "central_monitoring_state",
                _load_json(source_root / "central-monitoring.json"),
                _control_mappings(fixture_root, "oc.mon-01"),
                ["centralSinkConfigured", "scopedAssetsForwarded", "alertRulesEnabled"],
                {
                    "exportId": "exampleco-issued-monitoring-export-001",
                    "collectionMethod": "synthetic_export",
                    "sourcePath": "exports/monitoring/central-sink.json",
                    "digestAlgorithm": "sha256",
                },
            ),
            _system_claim(
                "EV-208",
                "encryption_at_rest_state",
                _load_json(source_root / "storage-encryption.json"),
                _control_mappings(fixture_root, "oc.crypt-01"),
                ["encryptionEnabled", "customerDataStoresCovered", "unencryptedStoresPresent"],
                {
                    "exportId": "exampleco-issued-storage-export-001",
                    "collectionMethod": "synthetic_export",
                    "sourcePath": "exports/storage/encryption-at-rest.json",
                    "digestAlgorithm": "sha256",
                },
            ),
            _human_claim(
                "EV-203",
                "training_attestation",
                _load_json(source_root / "training-attestation.json"),
                [
                    {
                        "framework": "ISO 27001",
                        "family": "awareness_and_training",
                        "controlId": "iso27001.family.awareness_and_training",
                    }
                ],
                ["trainingComplete", "completionWindowDays", "attestedPopulation"],
                {
                    "exportId": "exampleco-issued-training-attestation-001",
                    "collectionMethod": "signed_attestation",
                    "sourcePath": "/synthetic/hris/training",
                    "digestAlgorithm": "sha256",
                },
            ),
            _human_claim(
                "EV-204",
                "restore_test_attestation",
                _load_json(source_root / "restore-attestation.json"),
                [
                    {
                        "framework": "SOC 2",
                        "family": "backup_and_recovery",
                        "controlId": "soc2.family.backup_and_recovery",
                    },
                    {
                        "framework": "ISO 27001",
                        "family": "backup_and_recovery",
                        "controlId": "iso27001.family.backup_and_recovery",
                    },
                ],
                ["restoreTestCompleted", "testWindowDays", "scenarioId"],
                {
                    "exportId": "exampleco-issued-restore-attestation-001",
                    "collectionMethod": "signed_attestation",
                    "sourcePath": "/synthetic/dr/restore-tests",
                    "digestAlgorithm": "sha256",
                },
            ),
            _system_claim(
                "EV-205",
                "access_review_export",
                _load_json(source_root / "access-review-export.json"),
                _control_mappings(fixture_root, "oc.id-02"),
                ["reviewWindowDays", "reviewCompleted", "reviewPopulation"],
                {
                    "exportId": "exampleco-issued-access-review-export-001",
                    "collectionMethod": "synthetic_export",
                    "sourcePath": "exports/idp/access-review.json",
                    "digestAlgorithm": "sha256",
                },
            ),
            _human_claim(
                "EV-206",
                "access_review_closure_attestation",
                _load_json(source_root / "access-review-closure-attestation.json"),
                _control_mappings(fixture_root, "oc.id-03"),
                ["reviewCompleted", "reviewWindowDays", "reviewPopulation", "highRiskFindingsOpen"],
                {
                    "exportId": "exampleco-issued-access-review-closure-001",
                    "collectionMethod": "synthetic_attestation",
                    "sourcePath": "attestations/access-review-closure.json",
                    "digestAlgorithm": "sha256",
                },
            ),
            _human_claim(
                "EV-207",
                "incident_response_runbook_attestation",
                _load_json(source_root / "incident-runbook-attestation.json"),
                _control_mappings(fixture_root, "oc.ir-01"),
                ["runbookApproved", "ownerRole", "reviewWindowDays"],
                {
                    "exportId": "exampleco-issued-incident-runbook-001",
                    "collectionMethod": "synthetic_attestation",
                    "sourcePath": "attestations/incident-runbook.json",
                    "digestAlgorithm": "sha256",
                },
            ),
            _human_claim(
                "EV-214",
                "monitoring_review_attestation",
                _load_json(source_root / "monitoring-review-attestation.json"),
                _control_mappings(fixture_root, "oc.mon-02"),
                [
                    "alertReviewCadenceDeclared",
                    "monitoringOwnerRole",
                    "retentionOperationsCovered",
                    "reviewWindowDays",
                ],
                {
                    "exportId": "exampleco-issued-monitoring-review-001",
                    "collectionMethod": "synthetic_attestation",
                    "sourcePath": "attestations/monitoring-review.json",
                    "digestAlgorithm": "sha256",
                },
            ),
        ]
    if fixture == "cyber-baseline":
        return [
            _system_claim(
                "EV-601",
                "identity_mfa_enforcement",
                _load_json(source_root / "idp-admin-mfa.json"),
                _control_mappings(fixture_root, "oc.id-01"),
                ["mfaRequired", "conditionalAccessEnabled"],
                {
                    "exportId": "exampleco-cyber-baseline-idp-export-001",
                    "collectionMethod": "synthetic_export",
                    "sourcePath": "exports/idp/admin-identities.json",
                    "digestAlgorithm": "sha256",
                },
            ),
            _system_claim(
                "EV-602",
                "network_firewall_boundary",
                _load_json(source_root / "network-firewall.json"),
                _control_mappings(fixture_root, "oc.boundary-01"),
                [
                    "defaultDenyInbound",
                    "declaredIngressPorts",
                    "undeclaredIngressPresent",
                    "boundaryAttachedToIngressPath",
                    "adminIngressRestricted",
                    "approvedAdminSourceRanges",
                    "unapprovedAdminIngressPresent",
                ],
                {
                    "exportId": "exampleco-cyber-baseline-network-export-001",
                    "collectionMethod": "synthetic_export",
                    "sourcePath": "exports/network/firewall-boundary.json",
                    "digestAlgorithm": "sha256",
                },
            ),
            _system_claim(
                "EV-603",
                "secure_configuration_state",
                _load_json(source_root / "secure-configuration.json"),
                _control_mappings(fixture_root, "oc.cfg-01"),
                ["baselineApplied", "insecureDefaultsPresent", "snapshotAgeDays"],
                {
                    "exportId": "exampleco-cyber-baseline-config-export-001",
                    "collectionMethod": "synthetic_export",
                    "sourcePath": "exports/endpoints/secure-configuration.json",
                    "digestAlgorithm": "sha256",
                },
            ),
            _system_claim(
                "EV-604",
                "security_update_state",
                _load_json(source_root / "security-updates.json"),
                _control_mappings(fixture_root, "oc.patch-01"),
                ["supportedVersionsOnly", "criticalOverdueCount", "patchWindowDays"],
                {
                    "exportId": "exampleco-cyber-baseline-updates-export-001",
                    "collectionMethod": "synthetic_export",
                    "sourcePath": "exports/endpoints/security-updates.json",
                    "digestAlgorithm": "sha256",
                },
            ),
            _system_claim(
                "EV-605",
                "malware_protection_state",
                _load_json(source_root / "malware-protection.json"),
                _control_mappings(fixture_root, "oc.malware-01"),
                ["protectionEnabled", "signaturesCurrent", "tamperProtectionEnabled"],
                {
                    "exportId": "exampleco-cyber-baseline-malware-export-001",
                    "collectionMethod": "synthetic_export",
                    "sourcePath": "exports/endpoints/malware-protection.json",
                    "digestAlgorithm": "sha256",
                },
            ),
        ]
    if fixture == "ai-governance":
        return [
            _human_claim(
                "EV-701",
                "ai_context_attestation",
                _load_json(source_root / "ai-context-attestation.json"),
                _control_mappings(fixture_root, "oc.ai-01"),
                ["intendedUseDocumented", "deploymentContextDocumented", "ownerAssigned", "reviewWindowDays"],
                {
                    "exportId": "exampleco-ai-governance-context-attestation-001",
                    "collectionMethod": "synthetic_attestation",
                    "sourcePath": "attestations/ai/context.json",
                    "digestAlgorithm": "sha256",
                },
            ),
            _human_claim(
                "EV-702",
                "ai_risk_management_attestation",
                _load_json(source_root / "ai-risk-attestation.json"),
                _control_mappings(fixture_root, "oc.ai-02"),
                ["riskProcessDocumented", "riskTolerancesDeclared", "reviewWindowDays"],
                {
                    "exportId": "exampleco-ai-governance-risk-attestation-001",
                    "collectionMethod": "synthetic_attestation",
                    "sourcePath": "attestations/ai/risk-management.json",
                    "digestAlgorithm": "sha256",
                },
            ),
            _human_claim(
                "EV-703",
                "ai_human_oversight_attestation",
                _load_json(source_root / "ai-human-oversight-attestation.json"),
                _control_mappings(fixture_root, "oc.ai-03"),
                ["oversightRolesAssigned", "escalationPathDocumented", "overrideResponsibilityDeclared", "reviewWindowDays"],
                {
                    "exportId": "exampleco-ai-governance-oversight-attestation-001",
                    "collectionMethod": "synthetic_attestation",
                    "sourcePath": "attestations/ai/human-oversight.json",
                    "digestAlgorithm": "sha256",
                },
            ),
            _human_claim(
                "EV-704",
                "ai_monitoring_attestation",
                _load_json(source_root / "ai-monitoring-attestation.json"),
                _control_mappings(fixture_root, "oc.ai-04"),
                ["monitoringOwnerAssigned", "incidentEscalationPathDocumented", "reviewWindowDays"],
                {
                    "exportId": "exampleco-ai-governance-monitoring-attestation-001",
                    "collectionMethod": "synthetic_attestation",
                    "sourcePath": "attestations/ai/monitoring.json",
                    "digestAlgorithm": "sha256",
                },
            ),
            _system_claim(
                "EV-705",
                "ai_content_labeling_state",
                _load_json(source_root / "ai-content-labeling.json"),
                _control_mappings(fixture_root, "oc.ai-05"),
                ["labelingEnabled", "metadataMarkerEnabled", "enforcementChecksPassing"],
                {
                    "exportId": "exampleco-ai-governance-disclosure-export-001",
                    "collectionMethod": "synthetic_export",
                    "sourcePath": "exports/ai/content-labeling.json",
                    "digestAlgorithm": "sha256",
                },
            ),
        ]
    raise ValueError(f"File-based connectors are not yet defined for fixture {fixture}")
