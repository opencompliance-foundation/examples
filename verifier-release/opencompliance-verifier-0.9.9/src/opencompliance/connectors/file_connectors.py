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
            _human_claim(
                "EV-110A",
                "lawful_basis_register_attestation",
                _load_json(source_root / "lawful-basis-register-attestation.json"),
                _control_mappings(fixture_root, "oc.privacy-03"),
                [
                    "registerMaintained",
                    "purposeBoundariesDocumented",
                    "lawfulBasisAssigned",
                    "reviewWindowDays",
                ],
                {
                    "exportId": "attestation-exampleco-lawful-basis-2026-q1",
                    "collectionMethod": "synthetic_attestation",
                    "sourcePath": "attestations/lawful-basis-register-q1.json",
                    "digestAlgorithm": "sha256",
                },
            ),
            _human_claim(
                "EV-110B",
                "privacy_notice_attestation",
                _load_json(source_root / "privacy-notice-attestation.json"),
                _control_mappings(fixture_root, "oc.privacy-04"),
                [
                    "noticePublished",
                    "categoriesAndPurposesListed",
                    "rightsProcessLinked",
                    "reviewWindowDays",
                ],
                {
                    "exportId": "attestation-exampleco-privacy-notice-2026-q1",
                    "collectionMethod": "synthetic_attestation",
                    "sourcePath": "attestations/privacy-notice-q1.json",
                    "digestAlgorithm": "sha256",
                },
            ),
            _human_claim(
                "EV-110C",
                "privacy_impact_assessment_attestation",
                _load_json(source_root / "privacy-impact-assessment-attestation.json"),
                _control_mappings(fixture_root, "oc.privacy-05"),
                [
                    "assessmentCurrent",
                    "scopeDocumented",
                    "signoffAssigned",
                    "reviewWindowDays",
                ],
                {
                    "exportId": "attestation-exampleco-privacy-impact-2026-q1",
                    "collectionMethod": "synthetic_attestation",
                    "sourcePath": "attestations/privacy-impact-assessment-q1.json",
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
            _human_claim(
                "EV-134",
                "data_retention_schedule_attestation",
                _load_json(source_root / "data-retention-schedule-attestation.json"),
                _control_mappings(fixture_root, "oc.data-05"),
                ["scheduleDefined", "exceptionHandlingDefined", "reviewWindowDays"],
                {
                    "exportId": "attestation-exampleco-retention-schedule-2026-q1",
                    "collectionMethod": "synthetic_attestation",
                    "sourcePath": "attestations/data-retention-schedule-q1.json",
                    "digestAlgorithm": "sha256",
                },
            ),
            _human_claim(
                "EV-135",
                "security_commitment_terms_attestation",
                _load_json(source_root / "security-commitment-terms-attestation.json"),
                _control_mappings(fixture_root, "oc.vendor-07"),
                ["termsPresent", "agreementTypesCovered", "reviewWindowDays"],
                {
                    "exportId": "attestation-exampleco-security-commitment-terms-2026-q1",
                    "collectionMethod": "synthetic_attestation",
                    "sourcePath": "attestations/security-commitment-terms-q1.json",
                    "digestAlgorithm": "sha256",
                },
            ),
            _human_claim(
                "EV-136",
                "security_commitment_governance_attestation",
                _load_json(source_root / "security-commitment-governance-attestation.json"),
                _control_mappings(fixture_root, "oc.vendor-08"),
                ["ownerRole", "exceptionHandlingDefined", "reviewWindowDays"],
                {
                    "exportId": "attestation-exampleco-security-commitment-governance-2026-q1",
                    "collectionMethod": "synthetic_attestation",
                    "sourcePath": "attestations/security-commitment-governance-q1.json",
                    "digestAlgorithm": "sha256",
                },
            ),
            _human_claim(
                "EV-137",
                "outsourced_development_requirement_attestation",
                _load_json(source_root / "outsourced-development-requirement-attestation.json"),
                _control_mappings(fixture_root, "oc.vendor-10"),
                ["requirementsDefined", "relationshipScopeCount", "reviewWindowDays"],
                {
                    "exportId": "attestation-exampleco-outsourced-development-requirements-2026-q1",
                    "collectionMethod": "synthetic_attestation",
                    "sourcePath": "attestations/outsourced-development-requirements-q1.json",
                    "digestAlgorithm": "sha256",
                },
            ),
            _human_claim(
                "EV-138",
                "outsourced_development_review_attestation",
                _load_json(source_root / "outsourced-development-review-attestation.json"),
                _control_mappings(fixture_root, "oc.vendor-11"),
                ["oversightReviewPerformed", "exceptionHandlingDefined", "reviewWindowDays"],
                {
                    "exportId": "attestation-exampleco-outsourced-development-review-2026-q1",
                    "collectionMethod": "synthetic_attestation",
                    "sourcePath": "attestations/outsourced-development-review-q1.json",
                    "digestAlgorithm": "sha256",
                },
            ),
            _human_claim(
                "EV-139",
                "security_concern_intake_attestation",
                _load_json(source_root / "security-concern-intake-attestation.json"),
                _control_mappings(fixture_root, "oc.ir-04"),
                ["intakePathDefined", "ownerRole", "reviewWindowDays"],
                {
                    "exportId": "attestation-exampleco-security-concern-intake-2026-q1",
                    "collectionMethod": "synthetic_attestation",
                    "sourcePath": "attestations/security-concern-intake-q1.json",
                    "digestAlgorithm": "sha256",
                },
            ),
            _human_claim(
                "EV-140",
                "security_concern_resolution_attestation",
                _load_json(source_root / "security-concern-resolution-attestation.json"),
                _control_mappings(fixture_root, "oc.ir-05"),
                ["resolutionTrackingCurrent", "ownersAssigned", "reviewWindowDays"],
                {
                    "exportId": "attestation-exampleco-security-concern-resolution-2026-q1",
                    "collectionMethod": "synthetic_attestation",
                    "sourcePath": "attestations/security-concern-resolution-q1.json",
                    "digestAlgorithm": "sha256",
                },
            ),
            _system_claim(
                "EV-141",
                "remote_access_posture_state",
                _load_json(source_root / "remote-access-posture.json"),
                _control_mappings(fixture_root, "oc.remote-01"),
                ["remotePathDeclared", "devicePostureBounded", "systemCount"],
                {
                    "exportId": "export-exampleco-remote-access-2026-03-24-a",
                    "collectionMethod": "synthetic_export",
                    "sourcePath": "exports/remote/posture.json",
                    "digestAlgorithm": "sha256",
                },
            ),
            _human_claim(
                "EV-142",
                "remote_working_attestation",
                _load_json(source_root / "remote-working-attestation.json"),
                _control_mappings(fixture_root, "oc.remote-02"),
                ["procedureCurrent", "incidentReportingCovered", "reviewWindowDays"],
                {
                    "exportId": "attestation-exampleco-remote-working-2026-q1",
                    "collectionMethod": "synthetic_attestation",
                    "sourcePath": "attestations/remote-working-q1.json",
                    "digestAlgorithm": "sha256",
                },
            ),
            _human_claim(
                "EV-143",
                "compliance_requirement_register_attestation",
                _load_json(source_root / "compliance-requirement-register-attestation.json"),
                _control_mappings(fixture_root, "oc.cpl-01"),
                ["registerCurrent", "requirementClassesCovered", "reviewWindowDays"],
                {
                    "exportId": "attestation-exampleco-compliance-register-2026-q1",
                    "collectionMethod": "synthetic_attestation",
                    "sourcePath": "attestations/compliance-requirement-register-q1.json",
                    "digestAlgorithm": "sha256",
                },
            ),
            _human_claim(
                "EV-144",
                "compliance_requirement_review_attestation",
                _load_json(source_root / "compliance-requirement-review-attestation.json"),
                _control_mappings(fixture_root, "oc.cpl-02"),
                ["reviewCurrent", "ownerRole", "reviewWindowDays"],
                {
                    "exportId": "attestation-exampleco-compliance-review-2026-q1",
                    "collectionMethod": "synthetic_attestation",
                    "sourcePath": "attestations/compliance-requirement-review-q1.json",
                    "digestAlgorithm": "sha256",
                },
            ),
            _human_claim(
                "EV-145",
                "isms_stakeholder_register_attestation",
                _load_json(source_root / "isms-stakeholder-register-attestation.json"),
                _control_mappings(fixture_root, "oc.gov-33"),
                ["registerCurrent", "stakeholderGroupsCovered", "reviewWindowDays"],
                {
                    "exportId": "attestation-exampleco-isms-stakeholder-register-2026-q1",
                    "collectionMethod": "synthetic_attestation",
                    "sourcePath": "attestations/isms-stakeholder-register-q1.json",
                    "digestAlgorithm": "sha256",
                },
            ),
            _human_claim(
                "EV-146",
                "isms_stakeholder_obligation_attestation",
                _load_json(source_root / "isms-stakeholder-obligation-attestation.json"),
                _control_mappings(fixture_root, "oc.gov-34"),
                ["obligationsCurrent", "ownerRole", "reviewWindowDays"],
                {
                    "exportId": "attestation-exampleco-isms-stakeholder-obligations-2026-q1",
                    "collectionMethod": "synthetic_attestation",
                    "sourcePath": "attestations/isms-stakeholder-obligations-q1.json",
                    "digestAlgorithm": "sha256",
                },
            ),
            _human_claim(
                "EV-147",
                "project_security_requirement_attestation",
                _load_json(source_root / "project-security-requirement-attestation.json"),
                _control_mappings(fixture_root, "oc.proj-01"),
                ["requirementsDefined", "projectTypesCovered", "reviewWindowDays"],
                {
                    "exportId": "attestation-exampleco-project-security-requirements-2026-q1",
                    "collectionMethod": "synthetic_attestation",
                    "sourcePath": "attestations/project-security-requirements-q1.json",
                    "digestAlgorithm": "sha256",
                },
            ),
            _human_claim(
                "EV-148",
                "project_security_review_attestation",
                _load_json(source_root / "project-security-review-attestation.json"),
                _control_mappings(fixture_root, "oc.proj-02"),
                ["reviewPerformed", "exceptionsTracked", "reviewWindowDays"],
                {
                    "exportId": "attestation-exampleco-project-security-review-2026-q1",
                    "collectionMethod": "synthetic_attestation",
                    "sourcePath": "attestations/project-security-review-q1.json",
                    "digestAlgorithm": "sha256",
                },
            ),
            _human_claim(
                "EV-149",
                "customer_support_channel_attestation",
                _load_json(source_root / "customer-support-channel-attestation.json"),
                _control_mappings(fixture_root, "oc.ops-04"),
                ["channelsDocumented", "channelsReachable", "reviewWindowDays"],
                {
                    "exportId": "attestation-exampleco-customer-support-channels-2026-q1",
                    "collectionMethod": "synthetic_attestation",
                    "sourcePath": "attestations/customer-support-channels-q1.json",
                    "digestAlgorithm": "sha256",
                },
            ),
            _human_claim(
                "EV-150",
                "customer_support_governance_attestation",
                _load_json(source_root / "customer-support-governance-attestation.json"),
                _control_mappings(fixture_root, "oc.ops-05"),
                ["escalationOwnershipDefined", "reviewWindowDays", "staffingModelCurrent"],
                {
                    "exportId": "attestation-exampleco-customer-support-governance-2026-q1",
                    "collectionMethod": "synthetic_attestation",
                    "sourcePath": "attestations/customer-support-governance-q1.json",
                    "digestAlgorithm": "sha256",
                },
            ),
            _human_claim(
                "EV-151",
                "intellectual_property_policy_attestation",
                _load_json(source_root / "intellectual-property-policy-attestation.json"),
                _control_mappings(fixture_root, "oc.gov-39"),
                ["policyCurrent", "obligationClassesCovered", "reviewWindowDays"],
                {
                    "exportId": "attestation-exampleco-intellectual-property-policy-2026-q1",
                    "collectionMethod": "synthetic_attestation",
                    "sourcePath": "attestations/intellectual-property-policy-q1.json",
                    "digestAlgorithm": "sha256",
                },
            ),
            _human_claim(
                "EV-152",
                "intellectual_property_issue_attestation",
                _load_json(source_root / "intellectual-property-issue-attestation.json"),
                _control_mappings(fixture_root, "oc.gov-40"),
                ["handlingRulesCurrent", "ownerRole", "reviewWindowDays"],
                {
                    "exportId": "attestation-exampleco-intellectual-property-issues-2026-q1",
                    "collectionMethod": "synthetic_attestation",
                    "sourcePath": "attestations/intellectual-property-issues-q1.json",
                    "digestAlgorithm": "sha256",
                },
            ),
            _human_claim(
                "EV-153",
                "corrective_action_process_attestation",
                _load_json(source_root / "corrective-action-process-attestation.json"),
                _control_mappings(fixture_root, "oc.gov-36"),
                ["processDefined", "ownerRole", "reviewWindowDays"],
                {
                    "exportId": "attestation-exampleco-corrective-action-process-2026-q1",
                    "collectionMethod": "synthetic_attestation",
                    "sourcePath": "attestations/corrective-action-process-q1.json",
                    "digestAlgorithm": "sha256",
                },
            ),
            _human_claim(
                "EV-154",
                "corrective_action_followup_attestation",
                _load_json(source_root / "corrective-action-followup-attestation.json"),
                _control_mappings(fixture_root, "oc.gov-37"),
                ["followupCurrent", "ownersAssigned", "reviewWindowDays"],
                {
                    "exportId": "attestation-exampleco-corrective-action-followup-2026-q1",
                    "collectionMethod": "synthetic_attestation",
                    "sourcePath": "attestations/corrective-action-followup-q1.json",
                    "digestAlgorithm": "sha256",
                },
            ),
            _human_claim(
                "EV-155",
                "code_of_conduct_attestation",
                _load_json(source_root / "code-of-conduct-attestation.json"),
                _control_mappings(fixture_root, "oc.conduct-01"),
                ["acknowledgementsCurrent", "populationScope", "reviewWindowDays"],
                {
                    "exportId": "attestation-exampleco-code-of-conduct-2026-q1",
                    "collectionMethod": "synthetic_attestation",
                    "sourcePath": "attestations/code-of-conduct-q1.json",
                    "digestAlgorithm": "sha256",
                },
            ),
            _human_claim(
                "EV-156",
                "conduct_governance_attestation",
                _load_json(source_root / "conduct-governance-attestation.json"),
                _control_mappings(fixture_root, "oc.conduct-02"),
                [
                    "disciplinaryPathDefined",
                    "populationScope",
                    "refreshTriggersDefined",
                    "reviewWindowDays",
                ],
                {
                    "exportId": "attestation-exampleco-conduct-governance-2026-q1",
                    "collectionMethod": "synthetic_attestation",
                    "sourcePath": "attestations/conduct-governance-q1.json",
                    "digestAlgorithm": "sha256",
                },
            ),
            _human_claim(
                "EV-157",
                "disciplinary_policy_attestation",
                _load_json(source_root / "disciplinary-policy-attestation.json"),
                _control_mappings(fixture_root, "oc.hr-13"),
                ["policyCurrent", "populationsCovered", "reviewWindowDays"],
                {
                    "exportId": "attestation-exampleco-disciplinary-policy-2026-q1",
                    "collectionMethod": "synthetic_attestation",
                    "sourcePath": "attestations/disciplinary-policy-q1.json",
                    "digestAlgorithm": "sha256",
                },
            ),
            _human_claim(
                "EV-158",
                "disciplinary_action_attestation",
                _load_json(source_root / "disciplinary-action-attestation.json"),
                _control_mappings(fixture_root, "oc.hr-14"),
                ["actionRecordsCurrent", "reviewWindowDays", "reviewedBreachesCount"],
                {
                    "exportId": "attestation-exampleco-disciplinary-actions-2026-q1",
                    "collectionMethod": "synthetic_attestation",
                    "sourcePath": "attestations/disciplinary-actions-q1.json",
                    "digestAlgorithm": "sha256",
                },
            ),
            _human_claim(
                "EV-159",
                "internal_audit_program_attestation",
                _load_json(source_root / "internal-audit-program-attestation.json"),
                _control_mappings(fixture_root, "oc.audit-01"),
                ["programCurrent", "reviewWindowDays", "scheduleDefined"],
                {
                    "exportId": "attestation-exampleco-internal-audit-program-2026-q1",
                    "collectionMethod": "synthetic_attestation",
                    "sourcePath": "attestations/internal-audit-program-q1.json",
                    "digestAlgorithm": "sha256",
                },
            ),
            _human_claim(
                "EV-160",
                "internal_audit_execution_attestation",
                _load_json(source_root / "internal-audit-execution-attestation.json"),
                _control_mappings(fixture_root, "oc.audit-02"),
                ["findingsTracked", "followUpCurrent", "reviewWindowDays"],
                {
                    "exportId": "attestation-exampleco-internal-audit-execution-2026-q1",
                    "collectionMethod": "synthetic_attestation",
                    "sourcePath": "attestations/internal-audit-execution-q1.json",
                    "digestAlgorithm": "sha256",
                },
            ),
            _human_claim(
                "EV-161",
                "clear_desk_screen_policy_attestation",
                _load_json(source_root / "clear-desk-screen-policy-attestation.json"),
                _control_mappings(fixture_root, "oc.phys-01"),
                ["policyCurrent", "reviewWindowDays", "workspaceTypesCovered"],
                {
                    "exportId": "attestation-exampleco-clear-desk-policy-2026-q1",
                    "collectionMethod": "synthetic_attestation",
                    "sourcePath": "attestations/clear-desk-policy-q1.json",
                    "digestAlgorithm": "sha256",
                },
            ),
            _human_claim(
                "EV-162",
                "clear_desk_screen_coverage_attestation",
                _load_json(source_root / "clear-desk-screen-coverage-attestation.json"),
                _control_mappings(fixture_root, "oc.phys-02"),
                ["areasCovered", "communicationCurrent", "reviewWindowDays"],
                {
                    "exportId": "attestation-exampleco-clear-desk-coverage-2026-q1",
                    "collectionMethod": "synthetic_attestation",
                    "sourcePath": "attestations/clear-desk-coverage-q1.json",
                    "digestAlgorithm": "sha256",
                },
            ),
            _human_claim(
                "EV-163",
                "security_community_membership_attestation",
                _load_json(source_root / "security-community-membership-attestation.json"),
                _control_mappings(fixture_root, "oc.intel-01"),
                ["groupsCovered", "participationCurrent", "reviewWindowDays"],
                {
                    "exportId": "attestation-exampleco-security-community-membership-2026-q1",
                    "collectionMethod": "synthetic_attestation",
                    "sourcePath": "attestations/security-community-membership-q1.json",
                    "digestAlgorithm": "sha256",
                },
            ),
            _human_claim(
                "EV-164",
                "security_community_output_review_attestation",
                _load_json(source_root / "security-community-output-review-attestation.json"),
                _control_mappings(fixture_root, "oc.intel-02"),
                ["disseminationPathDefined", "ownerDefined", "reviewWindowDays"],
                {
                    "exportId": "attestation-exampleco-security-community-output-review-2026-q1",
                    "collectionMethod": "synthetic_attestation",
                    "sourcePath": "attestations/security-community-output-review-q1.json",
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
            _system_claim(
                "EV-706",
                "ai_content_provenance_state",
                _load_json(source_root / "ai-content-provenance.json"),
                _control_mappings(fixture_root, "oc.ai-06"),
                ["provenanceMetadataEnabled", "originHistoryRetained", "verificationChecksPassing"],
                {
                    "exportId": "exampleco-ai-governance-provenance-export-001",
                    "collectionMethod": "synthetic_export",
                    "sourcePath": "exports/ai/content-provenance.json",
                    "digestAlgorithm": "sha256",
                },
            ),
            _human_claim(
                "EV-707",
                "ai_evaluation_attestation",
                _load_json(source_root / "ai-evaluation-attestation.json"),
                _control_mappings(fixture_root, "oc.ai-07"),
                ["evaluationScopeDocumented", "testingLayersDocumented", "findingsCaptured", "reviewWindowDays"],
                {
                    "exportId": "exampleco-ai-governance-evaluation-attestation-001",
                    "collectionMethod": "synthetic_attestation",
                    "sourcePath": "attestations/ai/evaluation.json",
                    "digestAlgorithm": "sha256",
                },
            ),
            _human_claim(
                "EV-708",
                "ai_data_quality_attestation",
                _load_json(source_root / "ai-data-quality-attestation.json"),
                _control_mappings(fixture_root, "oc.ai-08"),
                ["dataSourcesEnumerated", "qualityCriteriaDocumented", "lineageDocumented", "stewardAssigned", "reviewWindowDays"],
                {
                    "exportId": "exampleco-ai-governance-data-quality-attestation-001",
                    "collectionMethod": "synthetic_attestation",
                    "sourcePath": "attestations/ai/data-quality.json",
                    "digestAlgorithm": "sha256",
                },
            ),
            _human_claim(
                "EV-709",
                "lawful_basis_register_attestation",
                _load_json(source_root / "lawful-basis-register-attestation.json"),
                _control_mappings(fixture_root, "oc.privacy-03"),
                [
                    "registerMaintained",
                    "purposeBoundariesDocumented",
                    "lawfulBasisAssigned",
                    "reviewWindowDays",
                ],
                {
                    "exportId": "exampleco-ai-governance-lawful-basis-attestation-001",
                    "collectionMethod": "synthetic_attestation",
                    "sourcePath": "attestations/privacy/lawful-basis.json",
                    "digestAlgorithm": "sha256",
                },
            ),
            _human_claim(
                "EV-710",
                "privacy_impact_assessment_attestation",
                _load_json(source_root / "privacy-impact-assessment-attestation.json"),
                _control_mappings(fixture_root, "oc.privacy-05"),
                [
                    "assessmentCurrent",
                    "scopeDocumented",
                    "signoffAssigned",
                    "reviewWindowDays",
                ],
                {
                    "exportId": "exampleco-ai-governance-privacy-impact-attestation-001",
                    "collectionMethod": "synthetic_attestation",
                    "sourcePath": "attestations/privacy/privacy-impact-assessment.json",
                    "digestAlgorithm": "sha256",
                },
            ),
            _human_claim(
                "EV-711",
                "ai_human_review_trigger_attestation",
                _load_json(source_root / "ai-human-review-trigger-attestation.json"),
                _control_mappings(fixture_root, "oc.ai-09"),
                [
                    "highImpactTriggerCriteriaDocumented",
                    "humanReviewOwnerAssigned",
                    "contestPathDocumented",
                    "reviewWindowDays",
                ],
                {
                    "exportId": "exampleco-ai-governance-human-review-trigger-attestation-001",
                    "collectionMethod": "synthetic_attestation",
                    "sourcePath": "attestations/ai/human-review-trigger.json",
                    "digestAlgorithm": "sha256",
                },
            ),
            _system_claim(
                "EV-713",
                "ai_task_envelope_state",
                _load_json(source_root / "ai-task-envelope.json"),
                _control_mappings(fixture_root, "oc.ai-11"),
                [
                    "purposeDeclared",
                    "allowedToolClassesDeclared",
                    "allowedDataClassesDeclared",
                    "retentionClassDeclared",
                    "humanReviewLinkagePresent",
                ],
                {
                    "exportId": "exampleco-ai-governance-task-envelope-export-001",
                    "collectionMethod": "synthetic_export",
                    "sourcePath": "exports/ai/task-envelope.json",
                    "digestAlgorithm": "sha256",
                },
            ),
            _system_claim(
                "EV-714",
                "ai_rights_ready_run_trace_state",
                _load_json(source_root / "ai-rights-ready-run-trace.json"),
                _control_mappings(fixture_root, "oc.ai-12"),
                [
                    "traceRetentionEnabled",
                    "requestPurposeCaptured",
                    "inputClassificationsCaptured",
                    "outputReferencesCaptured",
                    "humanReviewLinkagePresent",
                ],
                {
                    "exportId": "exampleco-ai-governance-rights-trace-export-001",
                    "collectionMethod": "synthetic_export",
                    "sourcePath": "exports/ai/rights-ready-run-trace.json",
                    "digestAlgorithm": "sha256",
                },
            ),
            _human_claim(
                "EV-715",
                "ai_supplier_transfer_attestation",
                _load_json(source_root / "ai-supplier-transfer-attestation.json"),
                _control_mappings(fixture_root, "oc.ai-13"),
                [
                    "supplierRegisterCurrent",
                    "subprocessorRolesDeclared",
                    "transferMechanismDeclared",
                    "reviewWindowDays",
                ],
                {
                    "exportId": "exampleco-ai-governance-supplier-transfer-attestation-001",
                    "collectionMethod": "synthetic_attestation",
                    "sourcePath": "attestations/ai/supplier-transfer.json",
                    "digestAlgorithm": "sha256",
                },
            ),
            _system_claim(
                "EV-716",
                "privacy_notice_publication_state",
                _load_json(source_root / "privacy-notice-publication.json"),
                _control_mappings(fixture_root, "oc.privacy-06"),
                [
                    "noticePublished",
                    "categoriesAndPurposesListed",
                    "rightsProcessLinked",
                    "noticeUrlReachable",
                    "reviewWindowDays",
                ],
                {
                    "exportId": "exampleco-ai-governance-notice-publication-export-001",
                    "collectionMethod": "synthetic_export",
                    "sourcePath": "exports/ai/privacy-notice-publication.json",
                    "digestAlgorithm": "sha256",
                },
            ),
        ]
    raise ValueError(f"File-based connectors are not yet defined for fixture {fixture}")
