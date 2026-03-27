from __future__ import annotations

from .actor_ontology import is_attestation_actor
from .models import FixtureSpec, FrameworkMapping, MixedControlSpec, VerificationItemSpec
from .release import PUBLIC_VERIFIER_VERSION


def _mfa(claim) -> bool:
    return claim.payload["mfaRequired"] is True and claim.payload["conditionalAccessEnabled"] is True


def _infrastructure_auth_uniqueness(claim) -> bool:
    return claim.payload["namedAccountsRequired"] is True and claim.payload["sharedAccountsPresent"] is False


def _environment_segmentation(claim) -> bool:
    return (
        claim.payload["customerBoundaryEnforced"] is True
        and claim.payload["productionSeparatedFromNonProduction"] is True
        and claim.payload["undeclaredCrossEnvironmentPathsPresent"] is False
    )


def _password_policy(claim) -> bool:
    return (
        claim.payload["minimumLengthAtLeast12"] is True
        and claim.payload["noMaximumLengthRestriction"] is True
        and claim.payload["commonPasswordBlockingEnabled"] is True
    )


def _web_application_firewall(claim) -> bool:
    return (
        claim.payload["wafAttachedToPublicIngress"] is True
        and claim.payload["blockingModeEnabled"] is True
        and claim.payload["managedRuleSetActive"] is True
    )


def _central_monitoring_state(claim) -> bool:
    return (
        claim.payload["centralSinkConfigured"] is True
        and claim.payload["scopedAssetsForwarded"] is True
        and claim.payload["alertRulesEnabled"] is True
    )


def _audit_logging(claim) -> bool:
    return claim.payload["auditLoggingEnabled"] is True and claim.payload["retentionDays"] > 0


def _tls_ingress(claim) -> bool:
    return (
        claim.payload["httpsOnly"] is True
        and claim.payload["managedCertificatesActive"] is True
        and claim.payload["minTlsVersion"] in {"1.2", "1.3"}
    )


def _plaintext_transport_disabled(claim) -> bool:
    return claim.payload["httpsOnly"] is True and claim.payload["plaintextDisabled"] is True


def _encryption_at_rest_state(claim) -> bool:
    return (
        claim.payload["encryptionEnabled"] is True
        and claim.payload["customerDataStoresCovered"] is True
        and claim.payload["unencryptedStoresPresent"] is False
    )


def _key_hygiene(claim) -> bool:
    return (
        claim.payload["userManagedKeysPresent"] is False
        and claim.payload["maxUserManagedKeyAgeDays"] == 0
    )


def _region_boundary(claim) -> bool:
    approved = set(claim.payload["approvedRegions"])
    observed = set(claim.payload["observedRegions"])
    return bool(approved) and bool(observed) and observed.issubset(approved) and claim.payload["undeclaredRegionsPresent"] is False


def _backup_schedule(claim) -> bool:
    return (
        claim.payload["snapshotsEnabled"] is True
        and claim.payload["snapshotFrequencyHours"] > 0
        and claim.payload["immutableWindowDays"] > 0
    )


def _access_review_export(claim) -> bool:
    return (
        claim.payload["reviewCompleted"] is True
        and claim.payload["reviewWindowDays"] > 0
        and bool(claim.payload["reviewPopulation"])
    )


def _repo_branch_protection(claim) -> bool:
    return (
        claim.payload["defaultBranchProtected"] is True
        and claim.payload["requiredApprovals"] > 0
        and claim.payload["statusChecksRequired"] is True
        and claim.payload["forcePushesBlocked"] is True
        and claim.payload["adminBypassRestricted"] is True
    )


def _ci_workflow_policy(claim) -> bool:
    return (
        claim.payload["workflowReviewRequired"] is True
        and claim.payload["trustedPublishingOnly"] is True
        and claim.payload["protectedRefsOnly"] is True
        and claim.payload["environmentApprovalsRequired"] is True
    )


def _network_firewall_boundary(claim) -> bool:
    return (
        claim.payload["defaultDenyInbound"] is True
        and len(claim.payload["declaredIngressPorts"]) > 0
        and claim.payload["undeclaredIngressPresent"] is False
    )


def _managed_ingress_boundary(claim) -> bool:
    return _network_firewall_boundary(claim) and claim.payload["boundaryAttachedToIngressPath"] is True


def _administrative_ingress_restricted(claim) -> bool:
    return (
        _network_firewall_boundary(claim)
        and claim.payload["adminIngressRestricted"] is True
        and len(claim.payload["approvedAdminSourceRanges"]) > 0
        and claim.payload["unapprovedAdminIngressPresent"] is False
    )


def _secure_configuration_state(claim) -> bool:
    return (
        claim.payload["baselineApplied"] is True
        and claim.payload["insecureDefaultsPresent"] is False
        and claim.payload["snapshotAgeDays"] <= 30
    )


def _security_update_state(claim) -> bool:
    return (
        claim.payload["supportedVersionsOnly"] is True
        and claim.payload["criticalOverdueCount"] == 0
        and claim.payload["patchWindowDays"] <= 14
    )


def _malware_protection_state(claim) -> bool:
    return (
        claim.payload["protectionEnabled"] is True
        and claim.payload["signaturesCurrent"] is True
        and claim.payload["tamperProtectionEnabled"] is True
    )


def _training_attestation(claim) -> bool:
    return claim.payload["trainingComplete"] is True and is_attestation_actor(claim.actor_type)


def _restore_attestation(claim) -> bool:
    return claim.payload["restoreTestCompleted"] is True and is_attestation_actor(claim.actor_type)


def _vendor_attestation(claim) -> bool:
    return (
        claim.payload["registerCurrent"] is True
        and claim.payload["dpaCoverageDeclared"] is True
        and is_attestation_actor(claim.actor_type)
    )


def _dsr_attestation(claim) -> bool:
    return claim.payload["runbookApproved"] is True and is_attestation_actor(claim.actor_type)


def _change_review_attestation(claim) -> bool:
    return (
        claim.payload["changeReviewPolicyApproved"] is True
        and claim.payload["emergencyChangeProcessDeclared"] is True
        and is_attestation_actor(claim.actor_type)
    )


def _access_review_closure_attestation(claim) -> bool:
    return (
        claim.payload["reviewCompleted"] is True
        and claim.payload["highRiskFindingsOpen"] == 0
        and is_attestation_actor(claim.actor_type)
    )


def _configuration_exception_attestation(claim) -> bool:
    return (
        claim.payload["exceptionRegisterCurrent"] is True
        and claim.payload["expiredExceptionsCount"] == 0
        and is_attestation_actor(claim.actor_type)
    )


def _patch_exception_attestation(claim) -> bool:
    return (
        claim.payload["exceptionRegisterCurrent"] is True
        and claim.payload["compensatingControlsDeclared"] is True
        and claim.payload["expiredExceptionsCount"] == 0
        and is_attestation_actor(claim.actor_type)
    )


def _incident_runbook_attestation(claim) -> bool:
    return (
        claim.payload["runbookApproved"] is True
        and bool(claim.payload["ownerRole"])
        and is_attestation_actor(claim.actor_type)
    )


def _incident_contact_matrix_attestation(claim) -> bool:
    return (
        claim.payload["contactsCurrent"] is True
        and claim.payload["escalationPathDocumented"] is True
        and is_attestation_actor(claim.actor_type)
    )


def _monitoring_review_attestation(claim) -> bool:
    return (
        claim.payload["alertReviewCadenceDeclared"] is True
        and bool(claim.payload["monitoringOwnerRole"])
        and claim.payload["retentionOperationsCovered"] is True
        and is_attestation_actor(claim.actor_type)
    )


def _vendor_security_terms_attestation(claim) -> bool:
    return (
        claim.payload["requiredSecurityTermsPresent"] is True
        and claim.payload["privacyTermsPresent"] is True
        and claim.payload["highRiskVendorsCovered"] > 0
        and is_attestation_actor(claim.actor_type)
    )


def _ai_context_attestation(claim) -> bool:
    return (
        claim.payload["intendedUseDocumented"] is True
        and claim.payload["deploymentContextDocumented"] is True
        and claim.payload["ownerAssigned"] is True
        and is_attestation_actor(claim.actor_type)
    )


def _ai_risk_management_attestation(claim) -> bool:
    return (
        claim.payload["riskProcessDocumented"] is True
        and claim.payload["riskTolerancesDeclared"] is True
        and is_attestation_actor(claim.actor_type)
    )


def _ai_human_oversight_attestation(claim) -> bool:
    return (
        claim.payload["oversightRolesAssigned"] is True
        and claim.payload["escalationPathDocumented"] is True
        and claim.payload["overrideResponsibilityDeclared"] is True
        and is_attestation_actor(claim.actor_type)
    )


def _ai_monitoring_attestation(claim) -> bool:
    return (
        claim.payload["monitoringOwnerAssigned"] is True
        and claim.payload["incidentEscalationPathDocumented"] is True
        and is_attestation_actor(claim.actor_type)
    )


def _ai_content_labeling_state(claim) -> bool:
    return (
        claim.payload["labelingEnabled"] is True
        and claim.payload["metadataMarkerEnabled"] is True
        and claim.payload["enforcementChecksPassing"] is True
    )


def _ai_content_provenance_state(claim) -> bool:
    return (
        claim.payload["provenanceMetadataEnabled"] is True
        and claim.payload["originHistoryRetained"] is True
        and claim.payload["verificationChecksPassing"] is True
    )


def _ai_evaluation_attestation(claim) -> bool:
    return (
        claim.payload["evaluationScopeDocumented"] is True
        and claim.payload["testingLayersDocumented"] is True
        and claim.payload["findingsCaptured"] is True
        and is_attestation_actor(claim.actor_type)
    )


def _ai_data_quality_attestation(claim) -> bool:
    return (
        claim.payload["dataSourcesEnumerated"] is True
        and claim.payload["qualityCriteriaDocumented"] is True
        and claim.payload["lineageDocumented"] is True
        and claim.payload["stewardAssigned"] is True
        and is_attestation_actor(claim.actor_type)
    )


MINIMAL_FIXTURE = FixtureSpec(
    fixture_name="minimal",
    bundle_id="exampleco-minimal-bundle-2026-03-24",
    generated_at="2026-03-24T00:05:00Z",
    verifier_version=PUBLIC_VERIFIER_VERSION,
    bundle_scope_note="Synthetic public-safe example proof bundle.",
    next_actions=[
        "Attach restore-test evidence as a typed claim.",
        "Separate documentary attestations from runtime proofs in the trust-surface output.",
    ],
    receipt_id="exampleco-minimal-receipt-2026-03-24",
    receipt_issued_at="2026-03-24T00:10:00Z",
    receipt_note="Synthetic public witness receipt for exact-match replay.",
    revocation_id="exampleco-minimal-revocation-2026-03-24",
    artifact_id="exampleco-minimal-certificate-001",
    revoked_at="2026-03-24T00:15:00Z",
    revocation_reason="Synthetic example of public revocation after drift or stale evidence.",
    trust_report_heading="# ExampleCo Minimal Trust-Surface Report",
    trust_report_why_lines=[
        "It is public-safe and synthetic, but it still demonstrates the core idea:",
        "",
        "- some things should be proved,",
        "- some should be attested,",
        "- some remain judgment,",
        "- and some are blocked by missing evidence.",
    ],
    items=[
        VerificationItemSpec(
            claim_id="EX-CLAIM-001",
            title="Administrative identities require MFA in the scoped production environment.",
            route="decidable",
            expected_claim_type="identity_mfa_enforcement",
            control_refs=["oc.id-01"],
            default_framework_mappings=[],
            basis_when_present="The identity provider export states MFA is required and conditional access is enabled.",
            basis_when_missing="No typed identity provider export is attached to this example corridor.",
            basis_when_failed="The identity provider export was present but did not satisfy the narrow MFA corridor.",
            predicate=_mfa,
            classification_rationale="Deterministic machine state over a narrow access-control predicate.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-002",
            title="Audit logging is enabled for the scoped production stack.",
            route="decidable",
            expected_claim_type="audit_logging_state",
            control_refs=["oc.log-01"],
            default_framework_mappings=[],
            basis_when_present="The cloud export states audit logging is enabled with a declared retention period.",
            basis_when_missing="No typed audit logging export is attached to this example corridor.",
            basis_when_failed="The cloud export was present but did not satisfy the audit-logging corridor predicate.",
            predicate=_audit_logging,
            classification_rationale="Deterministic machine state over a narrow logging predicate.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-003",
            title="Security awareness training completion is documented for the current review window.",
            route="attestation",
            expected_claim_type="training_attestation",
            control_refs=["oc.train-01"],
            default_framework_mappings=[],
            basis_when_present="The training claim is documentary and signed by a named human actor.",
            basis_when_missing="No typed training attestation is attached to this example corridor.",
            basis_when_failed="The training attestation was present but did not satisfy the current corridor predicate.",
            predicate=_training_attestation,
            classification_rationale="Documentary evidence with a human attestor rather than a decidable system invariant.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-004",
            title="The overall policy suite is adequate for the whole framework boundary.",
            route="judgment",
            expected_claim_type=None,
            control_refs=[],
            default_framework_mappings=[
                FrameworkMapping("SOC 2", "overall_control_adequacy"),
                FrameworkMapping("ISO 27001", "overall_control_adequacy"),
            ],
            basis_when_present=None,
            basis_when_missing="This remains an auditor and management judgment zone.",
            predicate=None,
            classification_rationale="Whole-program adequacy stays outside the machine-proof corridor.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-005",
            title="Restore testing has been performed in the last quarter.",
            route="attestation",
            expected_claim_type="restore_test_attestation",
            control_refs=["oc.rec-01"],
            default_framework_mappings=[
                FrameworkMapping("SOC 2", "backup_and_recovery", "soc2.family.backup_and_recovery"),
                FrameworkMapping("ISO 27001", "backup_and_recovery", "iso27001.family.backup_and_recovery"),
            ],
            basis_when_present="The restore exercise claim is documentary and signed by a named human actor.",
            basis_when_missing="No typed restore-test export is attached to this public example.",
            predicate=_restore_attestation,
            classification_rationale="Recovery evidence is attestation-routed in the current corridor.",
        ),
    ],
)


FAILED_FIXTURE = FixtureSpec(
    fixture_name="failed",
    bundle_id="exampleco-failed-bundle-2026-03-24",
    generated_at="2026-03-24T04:30:00Z",
    verifier_version=PUBLIC_VERIFIER_VERSION,
    bundle_scope_note="Synthetic public-safe ExampleCo proof bundle with present-but-failing evidence.",
    next_actions=[
        "Fix the cloud logging state so the failed claim can return to the proved corridor.",
        "Keep failed machine-state claims distinct from missing evidence in downstream artifacts.",
    ],
    receipt_id="exampleco-failed-receipt-2026-03-24",
    receipt_issued_at="2026-03-24T04:35:00Z",
    receipt_note="Synthetic public witness receipt for a failing ExampleCo corridor rerun.",
    revocation_id="exampleco-failed-revocation-2026-03-24",
    artifact_id="exampleco-failed-certificate-001",
    revoked_at="2026-03-24T04:40:00Z",
    revocation_reason="Synthetic example of failure-state publication after present but non-compliant machine evidence.",
    trust_report_heading="# ExampleCo Failed Trust-Surface Report",
    trust_report_why_lines=[
        "It is public-safe and synthetic, and it exists to prove the verifier can encode failure as data instead of crashing:",
        "",
        "- one claim is still proved,",
        "- one claim is present but failed,",
        "- one claim is attested,",
        "- and one claim remains judgment-routed.",
    ],
    items=[
        VerificationItemSpec(
            claim_id="EX-CLAIM-301",
            title="Administrative identities require MFA in the scoped production environment.",
            route="decidable",
            expected_claim_type="identity_mfa_enforcement",
            control_refs=["oc.id-01"],
            default_framework_mappings=[],
            basis_when_present="The identity provider export states MFA is required and conditional access is enabled.",
            basis_when_missing="No typed identity provider export is attached to this failed corridor.",
            basis_when_failed="The identity provider export was present but did not satisfy the narrow MFA corridor.",
            predicate=_mfa,
            classification_rationale="Deterministic machine state over a narrow access-control predicate.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-302",
            title="Audit logging is enabled for the scoped production stack.",
            route="decidable",
            expected_claim_type="audit_logging_state",
            control_refs=["oc.log-01"],
            default_framework_mappings=[],
            basis_when_present="The cloud export states audit logging is enabled with a declared retention period.",
            basis_when_missing="No typed audit logging export is attached to this failed corridor.",
            basis_when_failed="The cloud export was present, but audit logging was disabled or the retention window was invalid for the current corridor.",
            predicate=_audit_logging,
            classification_rationale="Deterministic machine state over a narrow logging predicate.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-303",
            title="Security awareness training completion is documented for the current review window.",
            route="attestation",
            expected_claim_type="training_attestation",
            control_refs=["oc.train-01"],
            default_framework_mappings=[],
            basis_when_present="The training claim is documentary and signed by a named human actor.",
            basis_when_missing="No typed training attestation is attached to this failed corridor.",
            basis_when_failed="The training attestation was present but did not satisfy the current corridor predicate.",
            predicate=_training_attestation,
            classification_rationale="Documentary evidence with a human attestor rather than a decidable system invariant.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-304",
            title="The overall policy suite is adequate for the whole framework boundary.",
            route="judgment",
            expected_claim_type=None,
            control_refs=[],
            default_framework_mappings=[
                FrameworkMapping("SOC 2", "overall_control_adequacy"),
                FrameworkMapping("ISO 27001", "overall_control_adequacy"),
            ],
            basis_when_present=None,
            basis_when_missing="This remains an auditor and management judgment zone.",
            predicate=None,
            classification_rationale="Whole-program adequacy stays outside the machine-proof corridor.",
        ),
    ],
)


MEDIUM_FIXTURE = FixtureSpec(
    fixture_name="medium",
    bundle_id="exampleco-medium-bundle-2026-03-24",
    generated_at="2026-03-24T01:25:00Z",
    verifier_version=PUBLIC_VERIFIER_VERSION,
    bundle_scope_note="Synthetic public-safe ExampleCo proof bundle for a wider multi-framework corridor.",
    next_actions=[
        "Promote the remaining imported availability, vulnerability-management, and secure-engineering seed controls after the current identity, perimeter, and monitoring wave.",
        "Keep privacy-by-design adequacy explicit as judgment rather than flattening it into a green check.",
        "Pin the same inputs and outputs in the witness receipt for replay.",
    ],
    receipt_id="exampleco-medium-receipt-2026-03-24",
    receipt_issued_at="2026-03-24T01:30:00Z",
    receipt_note="Synthetic public witness receipt for the richer ExampleCo corridor.",
    revocation_id="exampleco-medium-revocation-2026-03-24",
    artifact_id="exampleco-medium-certificate-001",
    revoked_at="2026-03-24T01:35:00Z",
    revocation_reason="Synthetic example of revocation after drift, stale attestations, or a replay mismatch.",
    trust_report_heading="# ExampleCo Medium Trust-Surface Report",
    trust_report_why_lines=[
        "It is public-safe and synthetic, but it demonstrates a more serious corridor than the minimal pack:",
        "",
        "- multi-framework family mappings,",
        "- explicit control references back into the synthetic OpenCompliance catalog,",
        "- a cleaner split between runtime proofs and signed attestations,",
        "- a deeper ISO 27001 and SOC 2 overlap slice for perimeter, centralized monitoring, ingress-boundary, and transport controls,",
        "- a first public mixed-control decomposition for change management,",
        "- and a still-honest boundary where legal or adequacy judgment remains human.",
    ],
    mixed_controls=[
        MixedControlSpec(
            control_id="oc.change-01",
            title="Production change control decomposes into machine policy checks plus signed governance evidence.",
            rationale="The current corridor can prove repository and CI guardrails, but wider change-review governance still arrives as signed human evidence rather than a theorem over system state.",
            sub_claim_ids=["EX-CLAIM-113", "EX-CLAIM-114", "EX-CLAIM-115"],
        )
    ],
    items=[
        VerificationItemSpec(
            claim_id="EX-CLAIM-101",
            title="Administrative identities require MFA and conditional access in the scoped production environment.",
            route="decidable",
            expected_claim_type="identity_mfa_enforcement",
            control_refs=["oc.id-01"],
            default_framework_mappings=[],
            basis_when_present="The synthetic identity export shows MFA required and conditional access enabled for scoped administrative identities.",
            basis_when_missing="No typed identity export is attached to this synthetic corridor.",
            predicate=_mfa,
            classification_rationale="Deterministic machine state over a narrow identity predicate.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-128",
            title="Infrastructure access in the scoped production environment requires unique named identities with no shared administrative accounts.",
            route="decidable",
            expected_claim_type="infrastructure_auth_uniqueness_state",
            control_refs=["oc.id-04"],
            default_framework_mappings=[],
            basis_when_present="The identity export shows named accounts required for the scoped infrastructure access plane and no shared administrative accounts present.",
            basis_when_missing="No typed infrastructure-auth export is attached to this synthetic corridor.",
            basis_when_failed="The identity export was present but did not satisfy the narrow unique-authentication predicate for scoped infrastructure access.",
            predicate=_infrastructure_auth_uniqueness,
            classification_rationale="Deterministic identity-state evidence over a narrow unique-authentication predicate.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-129",
            title="Scoped customer and environment boundaries are enforced with no undeclared cross-environment paths in the production slice.",
            route="decidable",
            expected_claim_type="environment_segmentation_state",
            control_refs=["oc.seg-01"],
            default_framework_mappings=[],
            basis_when_present="The architecture export shows customer boundaries enforced, production separated from non-production, and no undeclared cross-environment paths in scope.",
            basis_when_missing="No typed environment-segmentation export is attached to this synthetic corridor.",
            basis_when_failed="The environment-segmentation export was present but did not satisfy the narrow scoped boundary predicate.",
            predicate=_environment_segmentation,
            classification_rationale="Deterministic architecture-state evidence over a narrow tenant and environment segmentation predicate.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-130",
            title="Scoped password-quality controls enforce strong minimum length, no maximum-length restriction, and common-password blocking.",
            route="decidable",
            expected_claim_type="password_policy_state",
            control_refs=["oc.id-05"],
            default_framework_mappings=[],
            basis_when_present="The identity export shows a minimum password length of at least 12 characters, no maximum-length restriction, and common-password blocking enabled for the scoped accounts.",
            basis_when_missing="No typed password-policy export is attached to this synthetic corridor.",
            basis_when_failed="The password-policy export was present but did not satisfy the narrow scoped password-quality predicate.",
            predicate=_password_policy,
            classification_rationale="Deterministic identity-policy evidence over a narrow password-quality predicate.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-131",
            title="A managed web application firewall is attached to the scoped public ingress path, runs in blocking mode, and has a managed rule set active.",
            route="decidable",
            expected_claim_type="web_application_firewall_state",
            control_refs=["oc.web-01"],
            default_framework_mappings=[],
            basis_when_present="The edge export shows a managed web application firewall attached to the scoped public ingress path, running in blocking mode, with the managed rule set active.",
            basis_when_missing="No typed web-application-firewall export is attached to this synthetic corridor.",
            basis_when_failed="The web-application-firewall export was present but did not satisfy the narrow scoped perimeter predicate.",
            predicate=_web_application_firewall,
            classification_rationale="Deterministic perimeter-state evidence over a narrow managed-WAF predicate.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-102",
            title="Audit logging is enabled with a declared retention window for the scoped production runtime.",
            route="decidable",
            expected_claim_type="audit_logging_state",
            control_refs=["oc.log-01"],
            default_framework_mappings=[],
            basis_when_present="The cloud logging export shows logging enabled and retention declared for the scoped runtime.",
            basis_when_missing="No typed logging export is attached to this synthetic corridor.",
            predicate=_audit_logging,
            classification_rationale="Deterministic machine state over a narrow logging predicate.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-132",
            title="Scoped runtime telemetry is forwarded to the declared central monitoring sink with detection rules enabled.",
            route="decidable",
            expected_claim_type="central_monitoring_state",
            control_refs=["oc.mon-01"],
            default_framework_mappings=[],
            basis_when_present="The monitoring export shows the scoped assets forwarding telemetry into the declared central sink with detection rules enabled.",
            basis_when_missing="No typed centralized-monitoring export is attached to this synthetic corridor.",
            basis_when_failed="The centralized-monitoring export was present but did not satisfy the narrow central-sink predicate for the scoped assets.",
            predicate=_central_monitoring_state,
            classification_rationale="Deterministic telemetry-state evidence over a narrow centralized-monitoring predicate.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-103",
            title="Public ingress is HTTPS-only with managed certificates and TLS 1.2 or higher.",
            route="decidable",
            expected_claim_type="tls_ingress_configuration",
            control_refs=["oc.net-01"],
            default_framework_mappings=[],
            basis_when_present="The ingress export states HTTPS-only listeners, managed certificates, and a minimum TLS version of 1.2.",
            basis_when_missing="No typed ingress TLS export is attached to this synthetic corridor.",
            predicate=_tls_ingress,
            classification_rationale="Deterministic edge configuration over a narrow TLS predicate.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-124",
            title="The managed network boundary is attached to the declared ingress path for scoped public services.",
            route="decidable",
            expected_claim_type="network_firewall_boundary",
            control_refs=["oc.net-02"],
            default_framework_mappings=[],
            basis_when_present="The network boundary export shows the declared ingress path traverses the managed default-deny boundary.",
            basis_when_missing="No typed network boundary export is attached to this synthetic corridor.",
            basis_when_failed="The network boundary export was present but did not prove that the scoped ingress path traverses the managed boundary.",
            predicate=_managed_ingress_boundary,
            classification_rationale="Deterministic ingress-path attachment state over a narrow managed-boundary predicate.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-125",
            title="Administrative ingress is restricted to approved source ranges at the managed network boundary.",
            route="decidable",
            expected_claim_type="network_firewall_boundary",
            control_refs=["oc.net-03"],
            default_framework_mappings=[],
            basis_when_present="The network boundary export shows admin ingress restricted to declared source ranges with no unapproved admin exposure.",
            basis_when_missing="No typed network boundary export is attached to this synthetic corridor.",
            basis_when_failed="The network boundary export was present but did not satisfy the narrow approved-source restriction predicate.",
            predicate=_administrative_ingress_restricted,
            classification_rationale="Deterministic ingress-rule state over a narrow approved-source restriction predicate.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-126",
            title="Plaintext transport is disabled on the scoped public ingress path.",
            route="decidable",
            expected_claim_type="tls_ingress_configuration",
            control_refs=["oc.net-04"],
            default_framework_mappings=[],
            basis_when_present="The ingress export shows HTTPS-only listeners and an explicit plaintext-disabled transport policy.",
            basis_when_missing="No typed ingress TLS export is attached to this synthetic corridor.",
            basis_when_failed="The ingress export was present but did not show plaintext transport disabled for the scoped edge path.",
            predicate=_plaintext_transport_disabled,
            classification_rationale="Deterministic transport-policy state over a narrow plaintext-disabled predicate.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-127",
            title="Encryption at rest is enabled for the scoped customer data stores and no unencrypted store is present.",
            route="decidable",
            expected_claim_type="encryption_at_rest_state",
            control_refs=["oc.crypt-01"],
            default_framework_mappings=[],
            basis_when_present="The storage export shows encryption enabled across the scoped customer data stores and no unencrypted store present in the declared slice.",
            basis_when_missing="No typed storage-encryption export is attached to this synthetic corridor.",
            basis_when_failed="The storage export was present but did not satisfy the narrow encryption-at-rest predicate for the scoped customer data stores.",
            predicate=_encryption_at_rest_state,
            classification_rationale="Deterministic storage-configuration state over a narrow encryption-at-rest predicate.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-104",
            title="Scoped runtime service accounts do not use user-managed long-lived keys.",
            route="decidable",
            expected_claim_type="service_account_key_hygiene",
            control_refs=["oc.key-01"],
            default_framework_mappings=[],
            basis_when_present="The IAM export states no user-managed keys are present for the scoped runtime service accounts.",
            basis_when_missing="No typed machine-credential export is attached to this synthetic corridor.",
            predicate=_key_hygiene,
            classification_rationale="Deterministic machine credential state over a narrow key-hygiene predicate.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-105",
            title="The scoped workload runs only in the declared approved regions.",
            route="decidable",
            expected_claim_type="approved_region_deployment",
            control_refs=["oc.loc-01"],
            default_framework_mappings=[],
            basis_when_present="The asset inventory export shows observed regions match the declared approved region list and no undeclared regions are present.",
            basis_when_missing="No typed region inventory export is attached to this synthetic corridor.",
            predicate=_region_boundary,
            classification_rationale="Deterministic deployment-boundary state over a narrow location predicate.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-106",
            title="Backup snapshots are scheduled with a declared immutable retention window.",
            route="decidable",
            expected_claim_type="backup_snapshot_schedule",
            control_refs=["oc.backup-01"],
            default_framework_mappings=[],
            basis_when_present="The backup configuration export shows snapshots enabled with a 24-hour schedule and a declared immutable window.",
            basis_when_missing="No typed backup schedule export is attached to this synthetic corridor.",
            predicate=_backup_schedule,
            classification_rationale="Deterministic backup configuration over a narrow recovery predicate.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-107",
            title="Security awareness completion is documented for the current review period.",
            route="attestation",
            expected_claim_type="training_attestation",
            control_refs=["oc.train-01"],
            default_framework_mappings=[],
            basis_when_present="The training claim is a signed synthetic attestation by the named security manager.",
            basis_when_missing="No typed training attestation is attached to this synthetic corridor.",
            predicate=_training_attestation,
            classification_rationale="Documentary training evidence is attestation-routed in the current corridor.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-108",
            title="A restore exercise is documented inside the declared review window.",
            route="attestation",
            expected_claim_type="restore_test_attestation",
            control_refs=["oc.rec-01"],
            default_framework_mappings=[],
            basis_when_present="The restore exercise claim is a signed synthetic attestation by the platform lead.",
            basis_when_missing="No typed restore exercise attestation is attached to this synthetic corridor.",
            predicate=_restore_attestation,
            classification_rationale="Recovery exercise evidence is attestation-routed in the current corridor.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-109",
            title="The processor register is current and DPA coverage is declared for the reviewed subprocessors.",
            route="attestation",
            expected_claim_type="vendor_register_attestation",
            control_refs=["oc.vendor-01"],
            default_framework_mappings=[],
            basis_when_present="The vendor register claim is a signed synthetic attestation by the privacy manager.",
            basis_when_missing="No typed processor-register attestation is attached to this synthetic corridor.",
            predicate=_vendor_attestation,
            classification_rationale="Third-party and processor evidence is currently documentary rather than machine-proved.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-110",
            title="The DSR runbook is approved and has a named owner for the current review window.",
            route="attestation",
            expected_claim_type="dsr_runbook_attestation",
            control_refs=["oc.privacy-01"],
            default_framework_mappings=[],
            basis_when_present="The DSR runbook claim is a signed synthetic attestation by the privacy manager.",
            basis_when_missing="No typed DSR runbook attestation is attached to this synthetic corridor.",
            predicate=_dsr_attestation,
            classification_rationale="Privacy operations documentation is currently attestation-routed.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-111",
            title="Privacy-by-design adequacy has been demonstrated for the full product change process.",
            route="judgment",
            expected_claim_type=None,
            control_refs=["oc.privacy-02"],
            default_framework_mappings=[
                FrameworkMapping("GDPR", "privacy_by_design_and_default", "gdpr.family.privacy_by_design_and_default"),
            ],
            basis_when_present=None,
            basis_when_missing="This remains a human adequacy and interpretation zone that the public synthetic corridor does not reduce to a proof.",
            predicate=None,
            classification_rationale="Privacy-by-design adequacy remains explicitly outside the machine-proof corridor.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-112",
            title="A typed export of periodic access review evidence is present for the current review window.",
            route="decidable",
            expected_claim_type="access_review_export",
            control_refs=["oc.id-02"],
            default_framework_mappings=[
                FrameworkMapping("SOC 2", "access_control", "soc2.family.access_control"),
                FrameworkMapping("ISO 27001", "identity_and_access_management", "iso27001.family.identity_and_access_management"),
                FrameworkMapping("IRAP", "identity_access", "irap.family.identity_access"),
            ],
            basis_when_present="The access review export shows the declared review window was completed.",
            basis_when_missing="The corridor expects a typed access-review export, but no such evidence is attached to this public synthetic pack.",
            predicate=_access_review_export,
            classification_rationale="Periodic access review can be machine-checked only when a typed export exists.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-113",
            title="Default branch protections are enforced for the scoped production repository.",
            route="decidable",
            expected_claim_type="repo_branch_protection",
            control_refs=["oc.repo-01"],
            default_framework_mappings=[],
            basis_when_present="The repository export shows the default branch is protected, approvals are required, status checks are enforced, and force pushes are blocked.",
            basis_when_missing="No typed repository branch-protection export is attached to this synthetic corridor.",
            predicate=_repo_branch_protection,
            classification_rationale="Deterministic repository policy state over a narrow branch-protection predicate.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-114",
            title="CI workflow policy constrains deployment to reviewed workflows and protected refs.",
            route="decidable",
            expected_claim_type="ci_workflow_policy",
            control_refs=["oc.ci-01"],
            default_framework_mappings=[],
            basis_when_present="The CI export shows workflow review, trusted publishing, protected refs, and environment approvals are all required.",
            basis_when_missing="No typed CI workflow-policy export is attached to this synthetic corridor.",
            predicate=_ci_workflow_policy,
            classification_rationale="Deterministic delivery-policy state over a narrow CI workflow predicate.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-115",
            title="The production change-review policy is approved and declares an emergency change path for the current review window.",
            route="attestation",
            expected_claim_type="change_review_attestation",
            control_refs=["oc.change-02"],
            default_framework_mappings=[],
            basis_when_present="The change-review governance claim is a signed synthetic attestation by the named change owner.",
            basis_when_missing="No typed change-review governance attestation is attached to this synthetic corridor.",
            predicate=_change_review_attestation,
            classification_rationale="The wider change-review governance layer is still documentary even when repo and CI guardrails are machine-checked.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-116",
            title="Access review closure and high-risk exception resolution are attested for the current review window.",
            route="attestation",
            expected_claim_type="access_review_closure_attestation",
            control_refs=["oc.id-03"],
            default_framework_mappings=[],
            basis_when_present="The access-review closure claim is a signed synthetic attestation by the named identity governance owner.",
            basis_when_missing="No typed access-review closure attestation is attached to this synthetic corridor.",
            predicate=_access_review_closure_attestation,
            classification_rationale="Access-review closure is an accountable signoff activity and remains attestation-routed even when the export slice is machine-checkable.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-133",
            title="Monitoring review cadence, ownership, and retention operations are attested for the scoped production telemetry program.",
            route="attestation",
            expected_claim_type="monitoring_review_attestation",
            control_refs=["oc.mon-02"],
            default_framework_mappings=[],
            basis_when_present="The monitoring-operations claim is documentary and signed by the named detection engineering owner.",
            basis_when_missing="No typed monitoring-review attestation is attached to this synthetic corridor.",
            predicate=_monitoring_review_attestation,
            classification_rationale="Monitoring review operations remain documentary and owner-attested even when telemetry forwarding is machine-checkable.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-117",
            title="Configuration exceptions are current, owned, and not already expired in the current review window.",
            route="attestation",
            expected_claim_type="configuration_exception_attestation",
            control_refs=["oc.cfg-02"],
            default_framework_mappings=[],
            basis_when_present="The configuration-exception claim is a signed synthetic attestation by the named platform security owner.",
            basis_when_missing="No typed configuration-exception attestation is attached to this synthetic corridor.",
            predicate=_configuration_exception_attestation,
            classification_rationale="Baseline exception handling is a documentary governance slice and should stay separate from machine-checked hardening state.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-118",
            title="Patch exceptions declare compensating controls and no declared exception is already expired in the current review window.",
            route="attestation",
            expected_claim_type="patch_exception_attestation",
            control_refs=["oc.patch-02"],
            default_framework_mappings=[],
            basis_when_present="The patch-exception claim is a signed synthetic attestation by the named operations owner.",
            basis_when_missing="No typed patch-exception attestation is attached to this synthetic corridor.",
            predicate=_patch_exception_attestation,
            classification_rationale="Patch exception handling is documentary governance evidence rather than a runtime theorem.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-119",
            title="Patch cadence and exception thresholds are adequate for the in-scope production assets.",
            route="judgment",
            expected_claim_type=None,
            control_refs=["oc.patch-03"],
            default_framework_mappings=[
                FrameworkMapping("Cyber Essentials", "security_update_management", "cyber_essentials.family.security_update_management"),
                FrameworkMapping("NIST CSF 2.0", "software_maintenance_and_patch_management", "nist_csf_2_0.family.software_maintenance_and_patch_management"),
                FrameworkMapping("NIST SP 800-53 Rev. 5.1", "flaw_remediation", "nist_sp_800_53_rev_5_1.family.flaw_remediation"),
                FrameworkMapping("ISO 27001", "vulnerability_and_patch_management", "iso27001.family.vulnerability_and_patch_management"),
                FrameworkMapping("SOC 2", "vulnerability_management", "soc2.family.vulnerability_management"),
                FrameworkMapping("IRAP", "patch_and_vulnerability_management", "irap.family.patch_and_vulnerability_management"),
            ],
            basis_when_present=None,
            basis_when_missing="This remains a human adequacy zone. The public corridor does not reduce patch timelines, exception thresholds, or compensating-control sufficiency to a theorem.",
            predicate=None,
            classification_rationale="Patch adequacy stays explicitly judgment-routed even when patch state and exception records are structured.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-120",
            title="The incident response runbook is approved, owned, and current for the declared review window.",
            route="attestation",
            expected_claim_type="incident_response_runbook_attestation",
            control_refs=["oc.ir-01"],
            default_framework_mappings=[],
            basis_when_present="The incident-runbook claim is a signed synthetic attestation by the named security operations owner.",
            basis_when_missing="No typed incident-runbook attestation is attached to this synthetic corridor.",
            predicate=_incident_runbook_attestation,
            classification_rationale="Incident procedure ownership and approval are documentary facts and should stay attestation-routed.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-121",
            title="Incident escalation contacts and notification paths are current for the declared review window.",
            route="attestation",
            expected_claim_type="incident_contact_matrix_attestation",
            control_refs=["oc.ir-02"],
            default_framework_mappings=[],
            basis_when_present="The incident-contact claim is a signed synthetic attestation by the named security operations owner.",
            basis_when_missing="No typed incident-contact attestation is attached to this synthetic corridor.",
            predicate=_incident_contact_matrix_attestation,
            classification_rationale="Escalation paths and responder contacts remain documentary governance evidence in the current corridor.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-122",
            title="High-risk vendor agreements carry the required security and privacy terms for the current review window.",
            route="attestation",
            expected_claim_type="vendor_security_terms_attestation",
            control_refs=["oc.vendor-02"],
            default_framework_mappings=[],
            basis_when_present="The vendor-terms claim is a signed synthetic attestation by the named privacy and supplier-assurance owner.",
            basis_when_missing="No typed vendor-terms attestation is attached to this synthetic corridor.",
            predicate=_vendor_security_terms_attestation,
            classification_rationale="Contract-term presence is a documentary slice and should not be collapsed into a wider vendor-program claim.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-123",
            title="Vendor tiering, review cadence, and inherited-control allocation are adequate for the in-scope dependency set.",
            route="judgment",
            expected_claim_type=None,
            control_refs=["oc.vendor-03"],
            default_framework_mappings=[
                FrameworkMapping("SOC 2", "vendor_management", "soc2.family.vendor_management"),
                FrameworkMapping("ISO 27001", "supplier_relationships", "iso27001.family.supplier_relationships"),
                FrameworkMapping("GDPR", "processors_and_subprocessors", "gdpr.family.processors_and_subprocessors"),
            ],
            basis_when_present=None,
            basis_when_missing="This remains a human adequacy zone. The public corridor does not pretend to prove that vendor tiering, review cadence, or inherited-control allocation are sufficient.",
            predicate=None,
            classification_rationale="Vendor-program adequacy stays explicitly judgment-routed even when narrower vendor facts are structured.",
        ),
    ],
)


STALE_FIXTURE = FixtureSpec(
    fixture_name="stale",
    bundle_id="exampleco-stale-bundle-2026-03-24",
    generated_at="2026-03-24T05:20:00Z",
    verifier_version=PUBLIC_VERIFIER_VERSION,
    bundle_scope_note="Synthetic public-safe ExampleCo proof bundle with freshness blockers in an otherwise narrow corridor.",
    next_actions=[
        "Refresh the expired cloud logging export before rerunning Verify.",
        "Renew the expired training attestation instead of silently treating it as current.",
        "Keep stale evidence distinct from failed predicates and missing evidence in downstream artifacts.",
    ],
    receipt_id="exampleco-stale-receipt-2026-03-24",
    receipt_issued_at="2026-03-24T05:25:00Z",
    receipt_note="Synthetic public witness receipt for a freshness-blocked ExampleCo corridor rerun.",
    revocation_id="exampleco-stale-revocation-2026-03-24",
    artifact_id="exampleco-stale-certificate-001",
    revoked_at="2026-03-24T05:30:00Z",
    revocation_reason="Synthetic example of revocation after evidence freshness expires before the next verification run.",
    trust_report_heading="# ExampleCo Stale-Evidence Trust-Surface Report",
    trust_report_why_lines=[
        "It is public-safe and synthetic, and it exists to prove the verifier downgrades expired evidence instead of silently accepting it:",
        "",
        "- one claim is still proved,",
        "- one claim is still attested,",
        "- two claims are blocked because their evidence expired,",
        "- and the corridor therefore returns a punch-list rather than a certificate.",
    ],
    items=[
        VerificationItemSpec(
            claim_id="EX-CLAIM-401",
            title="Administrative identities require MFA in the scoped production environment.",
            route="decidable",
            expected_claim_type="identity_mfa_enforcement",
            control_refs=["oc.id-01"],
            default_framework_mappings=[],
            basis_when_present="The identity provider export states MFA is required and conditional access is enabled.",
            basis_when_missing="No typed identity provider export is attached to this stale corridor.",
            predicate=_mfa,
            classification_rationale="Deterministic machine state over a narrow access-control predicate.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-402",
            title="Audit logging is enabled for the scoped production stack.",
            route="decidable",
            expected_claim_type="audit_logging_state",
            control_refs=["oc.log-01"],
            default_framework_mappings=[],
            basis_when_present="The cloud export states audit logging is enabled with a declared retention period.",
            basis_when_missing="No typed audit logging export is attached to this stale corridor.",
            basis_when_stale="The cloud logging export exists, but its freshness window expired before this verification run.",
            predicate=_audit_logging,
            classification_rationale="Deterministic machine state over a narrow logging predicate, but only while the export is still fresh.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-403",
            title="Security awareness training completion is documented for the current review window.",
            route="attestation",
            expected_claim_type="training_attestation",
            control_refs=["oc.train-01"],
            default_framework_mappings=[],
            basis_when_present="The training claim is documentary and signed by a named human actor.",
            basis_when_missing="No typed training attestation is attached to this stale corridor.",
            basis_when_stale="The training attestation exists, but its freshness window expired before this verification run.",
            predicate=_training_attestation,
            classification_rationale="Documentary evidence with a human attestor remains valid only inside its declared freshness window.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-404",
            title="Restore testing has been performed in the declared review window.",
            route="attestation",
            expected_claim_type="restore_test_attestation",
            control_refs=["oc.rec-01"],
            default_framework_mappings=[],
            basis_when_present="The restore exercise claim is documentary and signed by a named human actor.",
            basis_when_missing="No typed restore-test attestation is attached to this stale corridor.",
            predicate=_restore_attestation,
            classification_rationale="Recovery evidence is attestation-routed in the current corridor.",
        ),
    ],
)


ISSUED_FIXTURE = FixtureSpec(
    fixture_name="issued",
    bundle_id="exampleco-issued-bundle-2026-03-24",
    generated_at="2026-03-24T02:10:00Z",
    verifier_version=PUBLIC_VERIFIER_VERSION,
    bundle_scope_note="Synthetic public-safe ExampleCo proof bundle with no blocking gaps in the narrow issued corridor.",
    next_actions=[
        "Keep the issued corridor narrow and explicit instead of over-claiming full framework coverage.",
        "Use the same narrow central-monitoring slice as a proof-carrying subset instead of treating full security-operations adequacy as proved.",
        "Publish the replay bundle and certificate artifacts alongside the trust-surface report.",
    ],
    receipt_id="exampleco-issued-receipt-2026-03-24",
    receipt_issued_at="2026-03-24T02:15:00Z",
    receipt_note="Synthetic public witness receipt for an exact-match replay of the issued ExampleCo corridor.",
    revocation_id="exampleco-issued-revocation-2026-03-24",
    artifact_id="exampleco-issued-certificate-001",
    revoked_at="2026-03-24T02:20:00Z",
    revocation_reason="Synthetic example of certificate revocation after later drift or stale attestation expiry.",
    trust_report_heading="# ExampleCo Issued Trust-Surface Report",
    trust_report_why_lines=[
        "It is public-safe and synthetic, and it exists to show the certificate path as cleanly as possible:",
        "",
        "- the corridor is intentionally narrow,",
        "- every in-scope claim is either proved or attested,",
        "- there are no missing-evidence blockers in this pack,",
        "- and the bundle stays honest about what remains outside scope.",
    ],
    items=[
        VerificationItemSpec(
            claim_id="EX-CLAIM-201",
            title="Administrative identities require MFA in the scoped production environment.",
            route="decidable",
            expected_claim_type="identity_mfa_enforcement",
            control_refs=["oc.id-01"],
            default_framework_mappings=[],
            basis_when_present="The identity provider export states MFA is required and conditional access is enabled.",
            basis_when_missing="No typed identity provider export is attached to this example corridor.",
            predicate=_mfa,
            classification_rationale="Deterministic machine state over a narrow access-control predicate.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-209",
            title="Infrastructure access in the scoped production environment requires unique named identities with no shared administrative accounts.",
            route="decidable",
            expected_claim_type="infrastructure_auth_uniqueness_state",
            control_refs=["oc.id-04"],
            default_framework_mappings=[],
            basis_when_present="The identity export shows named accounts required for the scoped infrastructure access plane and no shared administrative accounts present.",
            basis_when_missing="No typed infrastructure-auth export is attached to this example corridor.",
            basis_when_failed="The identity export was present but did not satisfy the narrow unique-authentication predicate for scoped infrastructure access.",
            predicate=_infrastructure_auth_uniqueness,
            classification_rationale="Deterministic identity-state evidence over a narrow unique-authentication predicate.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-210",
            title="Scoped customer and environment boundaries are enforced with no undeclared cross-environment paths in the production slice.",
            route="decidable",
            expected_claim_type="environment_segmentation_state",
            control_refs=["oc.seg-01"],
            default_framework_mappings=[],
            basis_when_present="The architecture export shows customer boundaries enforced, production separated from non-production, and no undeclared cross-environment paths in scope.",
            basis_when_missing="No typed environment-segmentation export is attached to this example corridor.",
            basis_when_failed="The environment-segmentation export was present but did not satisfy the narrow scoped boundary predicate.",
            predicate=_environment_segmentation,
            classification_rationale="Deterministic architecture-state evidence over a narrow tenant and environment segmentation predicate.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-211",
            title="Scoped password-quality controls enforce strong minimum length, no maximum-length restriction, and common-password blocking.",
            route="decidable",
            expected_claim_type="password_policy_state",
            control_refs=["oc.id-05"],
            default_framework_mappings=[],
            basis_when_present="The identity export shows a minimum password length of at least 12 characters, no maximum-length restriction, and common-password blocking enabled for the scoped accounts.",
            basis_when_missing="No typed password-policy export is attached to this example corridor.",
            basis_when_failed="The password-policy export was present but did not satisfy the narrow scoped password-quality predicate.",
            predicate=_password_policy,
            classification_rationale="Deterministic identity-policy evidence over a narrow password-quality predicate.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-212",
            title="A managed web application firewall is attached to the scoped public ingress path, runs in blocking mode, and has a managed rule set active.",
            route="decidable",
            expected_claim_type="web_application_firewall_state",
            control_refs=["oc.web-01"],
            default_framework_mappings=[],
            basis_when_present="The edge export shows a managed web application firewall attached to the scoped public ingress path, running in blocking mode, with the managed rule set active.",
            basis_when_missing="No typed web-application-firewall export is attached to this issued corridor.",
            basis_when_failed="The web-application-firewall export was present but did not satisfy the narrow scoped perimeter predicate.",
            predicate=_web_application_firewall,
            classification_rationale="Deterministic perimeter-state evidence over a narrow managed-WAF predicate.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-202",
            title="Audit logging is enabled for the scoped production stack.",
            route="decidable",
            expected_claim_type="audit_logging_state",
            control_refs=["oc.log-01"],
            default_framework_mappings=[],
            basis_when_present="The cloud export states audit logging is enabled with a declared retention period.",
            basis_when_missing="No typed audit logging export is attached to this example corridor.",
            predicate=_audit_logging,
            classification_rationale="Deterministic machine state over a narrow logging predicate.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-213",
            title="Scoped runtime telemetry is forwarded to the declared central monitoring sink with detection rules enabled.",
            route="decidable",
            expected_claim_type="central_monitoring_state",
            control_refs=["oc.mon-01"],
            default_framework_mappings=[],
            basis_when_present="The monitoring export shows the scoped stack forwarding telemetry into the declared central sink with detection rules enabled.",
            basis_when_missing="No typed centralized-monitoring export is attached to this issued corridor.",
            basis_when_failed="The centralized-monitoring export was present but did not satisfy the narrow central-sink predicate for the scoped stack.",
            predicate=_central_monitoring_state,
            classification_rationale="Deterministic telemetry-state evidence over a narrow centralized-monitoring predicate.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-208",
            title="Encryption at rest is enabled for the scoped customer data stores and no unencrypted store is present.",
            route="decidable",
            expected_claim_type="encryption_at_rest_state",
            control_refs=["oc.crypt-01"],
            default_framework_mappings=[],
            basis_when_present="The storage export shows encryption enabled across the scoped customer data stores and no unencrypted store present in the declared slice.",
            basis_when_missing="No typed storage-encryption export is attached to this issued corridor.",
            basis_when_failed="The storage export was present but did not satisfy the narrow encryption-at-rest predicate for the scoped customer data stores.",
            predicate=_encryption_at_rest_state,
            classification_rationale="Deterministic storage-configuration state over a narrow encryption-at-rest predicate.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-203",
            title="Security awareness training completion is documented for the current review window.",
            route="attestation",
            expected_claim_type="training_attestation",
            control_refs=["oc.train-01"],
            default_framework_mappings=[],
            basis_when_present="The training claim is documentary and signed by a named human actor.",
            basis_when_missing="No typed training attestation is attached to this example corridor.",
            predicate=_training_attestation,
            classification_rationale="Documentary evidence with a human attestor rather than a decidable system invariant.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-204",
            title="Restore testing has been performed in the declared review window.",
            route="attestation",
            expected_claim_type="restore_test_attestation",
            control_refs=["oc.rec-01"],
            default_framework_mappings=[],
            basis_when_present="The restore exercise claim is documentary and signed by a named human actor.",
            basis_when_missing="No typed restore-test attestation is attached to this example corridor.",
            predicate=_restore_attestation,
            classification_rationale="Recovery evidence is attestation-routed in the current corridor.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-205",
            title="A typed export of periodic access review evidence is present for the current review window.",
            route="decidable",
            expected_claim_type="access_review_export",
            control_refs=["oc.id-02"],
            default_framework_mappings=[
                FrameworkMapping("SOC 2", "access_control", "soc2.family.access_control"),
                FrameworkMapping("ISO 27001", "identity_and_access_management", "iso27001.family.identity_and_access_management"),
                FrameworkMapping("IRAP", "identity_access", "irap.family.identity_access"),
            ],
            basis_when_present="The access-review export shows the declared review window was completed for the scoped privileged identities.",
            basis_when_missing="No typed access-review export is attached to this issued corridor.",
            predicate=_access_review_export,
            classification_rationale="Periodic access review can be machine-checked when a typed export exists for the scoped population and window.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-206",
            title="Access review closure and high-risk exception resolution are attested for the current review window.",
            route="attestation",
            expected_claim_type="access_review_closure_attestation",
            control_refs=["oc.id-03"],
            default_framework_mappings=[],
            basis_when_present="The access-review closure claim is documentary and signed by the named identity governance owner.",
            basis_when_missing="No typed access-review closure attestation is attached to this issued corridor.",
            predicate=_access_review_closure_attestation,
            classification_rationale="Closure and exception signoff remain attestation-routed even when the review export itself is typed.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-207",
            title="The incident response runbook is approved, owned, and current for the declared review window.",
            route="attestation",
            expected_claim_type="incident_response_runbook_attestation",
            control_refs=["oc.ir-01"],
            default_framework_mappings=[],
            basis_when_present="The incident-runbook claim is documentary and signed by the named security operations owner.",
            basis_when_missing="No typed incident-runbook attestation is attached to this issued corridor.",
            predicate=_incident_runbook_attestation,
            classification_rationale="Incident runbook ownership and approval remain documentary facts in the current narrow issued corridor.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-214",
            title="Monitoring review cadence, ownership, and retention operations are attested for the scoped production telemetry program.",
            route="attestation",
            expected_claim_type="monitoring_review_attestation",
            control_refs=["oc.mon-02"],
            default_framework_mappings=[],
            basis_when_present="The monitoring-operations claim is documentary and signed by the named detection engineering owner.",
            basis_when_missing="No typed monitoring-review attestation is attached to this issued corridor.",
            predicate=_monitoring_review_attestation,
            classification_rationale="Monitoring review operations remain documentary and owner-attested even when telemetry forwarding is machine-checkable.",
        ),
    ],
)


CYBER_BASELINE_FIXTURE = FixtureSpec(
    fixture_name="cyber-baseline",
    bundle_id="exampleco-cyber-baseline-bundle-2026-03-24",
    generated_at="2026-03-24T06:10:00Z",
    verifier_version=PUBLIC_VERIFIER_VERSION,
    bundle_scope_note="Synthetic public-safe ExampleCo proof bundle for a narrow Cyber Essentials-style baseline corridor crosswalked to adjacent public cyber frameworks.",
    next_actions=[
        "Keep the cyber baseline corridor narrow and explicit instead of implying full Cyber Essentials certification.",
        "Add managed-device inventory typing so patching and malware evidence can be scoped per fleet slice rather than only per export.",
        "Promote the current family-proxy Cyber Essentials mappings to reviewed requirement-topic anchors where the public source text supports it.",
    ],
    receipt_id="exampleco-cyber-baseline-receipt-2026-03-24",
    receipt_issued_at="2026-03-24T06:15:00Z",
    receipt_note="Synthetic public witness receipt for an exact-match replay of the cyber baseline ExampleCo corridor.",
    revocation_id="exampleco-cyber-baseline-revocation-2026-03-24",
    artifact_id="exampleco-cyber-baseline-certificate-001",
    revoked_at="2026-03-24T06:20:00Z",
    revocation_reason="Synthetic example of cyber baseline certificate revocation after later drift, stale exports, or replay mismatch.",
    trust_report_heading="# ExampleCo Cyber Baseline Trust-Surface Report",
    trust_report_why_lines=[
        "It is public-safe and synthetic, and it exists to show a clean issued corridor for a narrow cyber hygiene baseline:",
        "",
        "- five machine-checkable controls,",
        "- a certificate path that stays narrow and explicit,",
        "- crosswalks into adjacent public cyber frameworks without claiming full-framework certification,",
        "- and a reusable ExampleCo pack that other teams can adapt without leaking real estate or endpoint data.",
    ],
    items=[
        VerificationItemSpec(
            claim_id="EX-CLAIM-601",
            title="Administrative identities require MFA and conditional access for the scoped managed admin boundary.",
            route="decidable",
            expected_claim_type="identity_mfa_enforcement",
            control_refs=["oc.id-01"],
            default_framework_mappings=[],
            basis_when_present="The identity export shows MFA required and conditional access enabled for scoped administrative identities.",
            basis_when_missing="No typed identity export is attached to this cyber baseline corridor.",
            basis_when_failed="The identity export was present but did not satisfy the narrow administrative MFA predicate.",
            predicate=_mfa,
            classification_rationale="Deterministic identity policy state over a narrow access-control predicate.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-602",
            title="The inbound network boundary defaults to deny and exposes only declared ingress ports.",
            route="decidable",
            expected_claim_type="network_firewall_boundary",
            control_refs=["oc.boundary-01"],
            default_framework_mappings=[],
            basis_when_present="The network boundary export shows default-deny inbound posture, declared ingress ports, and no undeclared exposure.",
            basis_when_missing="No typed network boundary export is attached to this cyber baseline corridor.",
            basis_when_failed="The network boundary export was present but did not satisfy the narrow default-deny ingress predicate.",
            predicate=_network_firewall_boundary,
            classification_rationale="Deterministic firewall and ingress policy state over a narrow boundary predicate.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-603",
            title="Secure baseline configuration is applied and insecure defaults are absent in the managed device set.",
            route="decidable",
            expected_claim_type="secure_configuration_state",
            control_refs=["oc.cfg-01"],
            default_framework_mappings=[],
            basis_when_present="The configuration export shows the approved baseline applied, insecure defaults absent, and a recent configuration snapshot.",
            basis_when_missing="No typed secure-configuration export is attached to this cyber baseline corridor.",
            basis_when_failed="The secure-configuration export was present but did not satisfy the narrow baseline predicate.",
            predicate=_secure_configuration_state,
            classification_rationale="Deterministic configuration state over a narrow hardening predicate.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-604",
            title="Supported versions are in use and no critical security updates are overdue in the managed device set.",
            route="decidable",
            expected_claim_type="security_update_state",
            control_refs=["oc.patch-01"],
            default_framework_mappings=[],
            basis_when_present="The update export shows supported versions only, no overdue critical patches, and a declared patch window inside the corridor threshold.",
            basis_when_missing="No typed security-update export is attached to this cyber baseline corridor.",
            basis_when_failed="The security-update export was present but did not satisfy the narrow patching predicate.",
            predicate=_security_update_state,
            classification_rationale="Deterministic patch and support-window state over a narrow update-management predicate.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-605",
            title="Malware protection is enabled, current, and tamper-protected on the managed device set.",
            route="decidable",
            expected_claim_type="malware_protection_state",
            control_refs=["oc.malware-01"],
            default_framework_mappings=[],
            basis_when_present="The endpoint protection export shows malware protection enabled, signatures current, and tamper protection active.",
            basis_when_missing="No typed malware-protection export is attached to this cyber baseline corridor.",
            basis_when_failed="The malware-protection export was present but did not satisfy the narrow endpoint protection predicate.",
            predicate=_malware_protection_state,
            classification_rationale="Deterministic endpoint protection state over a narrow malware-baseline predicate.",
        ),
    ],
)


AI_GOVERNANCE_FIXTURE = FixtureSpec(
    fixture_name="ai-governance",
    bundle_id="exampleco-ai-governance-bundle-2026-03-24",
    generated_at="2026-03-24T06:40:00Z",
    verifier_version=PUBLIC_VERIFIER_VERSION,
    bundle_scope_note="Synthetic public-safe ExampleCo proof bundle for a narrow AI governance corridor spanning documentary governance evidence, two machine-checkable transparency controls, and additional evaluation and data-governance attestations.",
    next_actions=[
        "Keep legal classification, fundamental-rights analysis, and prohibited-practice review outside the issued corridor unless they are explicitly modeled.",
        "Add typed purpose-bounded task-envelope, rights-ready run-trace, and supplier-transfer artifacts so more of the AI corridor can answer privacy and accountability questions directly.",
        "Promote the current EU and NIST family proxies to reviewed exact-anchor mappings where public source text supports that level of precision.",
    ],
    receipt_id="exampleco-ai-governance-receipt-2026-03-24",
    receipt_issued_at="2026-03-24T06:45:00Z",
    receipt_note="Synthetic public witness receipt for an exact-match replay of the AI governance ExampleCo corridor.",
    revocation_id="exampleco-ai-governance-revocation-2026-03-24",
    artifact_id="exampleco-ai-governance-certificate-001",
    revoked_at="2026-03-24T06:50:00Z",
    revocation_reason="Synthetic example of AI governance certificate revocation after stale documentation, disclosure drift, or replay mismatch.",
    trust_report_heading="# ExampleCo AI Governance Trust-Surface Report",
    trust_report_why_lines=[
        "It is public-safe and synthetic, and it exists to show what an honest AI governance corridor can look like today:",
        "",
        "- documentary governance evidence stays explicitly documentary,",
        "- disclosure and provenance configuration stay machine-checkable,",
        "- evaluation and data-governance evidence become visible without pretending they are theorems,",
        "- the issued artifact is still narrow and scoped rather than pretending to certify the whole AI Act,",
        "- and the corridor can be replayed and audited like the cyber examples.",
    ],
    items=[
        VerificationItemSpec(
            claim_id="EX-CLAIM-701",
            title="AI system intended use, deployment context, and named owner are documented for the current review window.",
            route="attestation",
            expected_claim_type="ai_context_attestation",
            control_refs=["oc.ai-01"],
            default_framework_mappings=[],
            basis_when_present="The AI context claim is a signed synthetic attestation covering intended use, deployment context, and accountable ownership.",
            basis_when_missing="No typed AI context attestation is attached to this AI governance corridor.",
            basis_when_failed="The AI context attestation was present but did not satisfy the current corridor predicate.",
            predicate=_ai_context_attestation,
            classification_rationale="Documentary governance evidence with a named human attestor rather than a decidable runtime invariant.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-702",
            title="AI risk management process and risk tolerances are documented for the current review window.",
            route="attestation",
            expected_claim_type="ai_risk_management_attestation",
            control_refs=["oc.ai-02"],
            default_framework_mappings=[],
            basis_when_present="The AI risk management claim is a signed synthetic attestation covering the documented process and declared risk tolerances.",
            basis_when_missing="No typed AI risk management attestation is attached to this AI governance corridor.",
            basis_when_failed="The AI risk management attestation was present but did not satisfy the current corridor predicate.",
            predicate=_ai_risk_management_attestation,
            classification_rationale="Documentary governance evidence for the current AI risk process remains attestation-routed.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-703",
            title="Human oversight roles, escalation path, and override responsibility are documented for the current review window.",
            route="attestation",
            expected_claim_type="ai_human_oversight_attestation",
            control_refs=["oc.ai-03"],
            default_framework_mappings=[],
            basis_when_present="The human oversight claim is a signed synthetic attestation covering roles, escalation, and override responsibility.",
            basis_when_missing="No typed AI human-oversight attestation is attached to this AI governance corridor.",
            basis_when_failed="The AI human-oversight attestation was present but did not satisfy the current corridor predicate.",
            predicate=_ai_human_oversight_attestation,
            classification_rationale="Human oversight remains documentary governance evidence in the current corridor.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-704",
            title="Post-deployment monitoring ownership and incident escalation are documented for the current review window.",
            route="attestation",
            expected_claim_type="ai_monitoring_attestation",
            control_refs=["oc.ai-04"],
            default_framework_mappings=[],
            basis_when_present="The AI monitoring claim is a signed synthetic attestation covering monitoring ownership and incident escalation.",
            basis_when_missing="No typed AI monitoring attestation is attached to this AI governance corridor.",
            basis_when_failed="The AI monitoring attestation was present but did not satisfy the current corridor predicate.",
            predicate=_ai_monitoring_attestation,
            classification_rationale="Post-deployment monitoring governance remains documentary in the current public corridor.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-705",
            title="AI-generated content disclosure is enabled and enforcement checks are passing on the public assistant surface.",
            route="decidable",
            expected_claim_type="ai_content_labeling_state",
            control_refs=["oc.ai-05"],
            default_framework_mappings=[],
            basis_when_present="The disclosure export shows visible labeling, metadata markers, and passing enforcement checks for the scoped assistant surface.",
            basis_when_missing="No typed AI content-labeling export is attached to this AI governance corridor.",
            basis_when_failed="The AI content-labeling export was present but did not satisfy the narrow disclosure predicate.",
            predicate=_ai_content_labeling_state,
            classification_rationale="Deterministic disclosure configuration over a narrow transparency predicate.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-706",
            title="AI-generated content provenance metadata is enabled and verification checks are passing on the public assistant surface.",
            route="decidable",
            expected_claim_type="ai_content_provenance_state",
            control_refs=["oc.ai-06"],
            default_framework_mappings=[],
            basis_when_present="The provenance export shows machine-readable provenance metadata, retained origin history, and passing verification checks for the scoped assistant surface.",
            basis_when_missing="No typed AI provenance export is attached to this AI governance corridor.",
            basis_when_failed="The AI provenance export was present but did not satisfy the narrow provenance predicate.",
            predicate=_ai_content_provenance_state,
            classification_rationale="Deterministic provenance-configuration state over a narrow transparency predicate.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-707",
            title="AI evaluation scope, testing layers, and findings capture are documented for the current review window.",
            route="attestation",
            expected_claim_type="ai_evaluation_attestation",
            control_refs=["oc.ai-07"],
            default_framework_mappings=[],
            basis_when_present="The AI evaluation claim is a signed synthetic attestation covering evaluation scope, testing layers, and findings capture.",
            basis_when_missing="No typed AI evaluation attestation is attached to this AI governance corridor.",
            basis_when_failed="The AI evaluation attestation was present but did not satisfy the current corridor predicate.",
            predicate=_ai_evaluation_attestation,
            classification_rationale="Evaluation design and findings remain documentary governance evidence in the current public corridor.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-708",
            title="AI data sources, quality criteria, and lineage stewardship are documented for the current review window.",
            route="attestation",
            expected_claim_type="ai_data_quality_attestation",
            control_refs=["oc.ai-08"],
            default_framework_mappings=[],
            basis_when_present="The AI data-governance claim is a signed synthetic attestation covering data sources, quality criteria, lineage notes, and named stewardship.",
            basis_when_missing="No typed AI data-quality attestation is attached to this AI governance corridor.",
            basis_when_failed="The AI data-quality attestation was present but did not satisfy the current corridor predicate.",
            predicate=_ai_data_quality_attestation,
            classification_rationale="Data-quality and lineage governance stay documentary in the current public corridor.",
        ),
    ],
)


FIXTURE_SPECS = {
    "minimal": MINIMAL_FIXTURE,
    "failed": FAILED_FIXTURE,
    "medium": MEDIUM_FIXTURE,
    "stale": STALE_FIXTURE,
    "issued": ISSUED_FIXTURE,
    "cyber-baseline": CYBER_BASELINE_FIXTURE,
    "ai-governance": AI_GOVERNANCE_FIXTURE,
}
