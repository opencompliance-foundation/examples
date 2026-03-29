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


def _remote_access_posture_state(claim) -> bool:
    return (
        claim.payload["remotePathDeclared"] is True
        and claim.payload["devicePostureBounded"] is True
        and claim.payload["systemCount"] > 0
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


def _lawful_basis_register_attestation(claim) -> bool:
    return (
        claim.payload["registerMaintained"] is True
        and claim.payload["purposeBoundariesDocumented"] is True
        and claim.payload["lawfulBasisAssigned"] is True
        and is_attestation_actor(claim.actor_type)
    )


def _privacy_notice_attestation(claim) -> bool:
    return (
        claim.payload["noticePublished"] is True
        and claim.payload["categoriesAndPurposesListed"] is True
        and claim.payload["rightsProcessLinked"] is True
        and is_attestation_actor(claim.actor_type)
    )


def _privacy_impact_assessment_attestation(claim) -> bool:
    return (
        claim.payload["assessmentCurrent"] is True
        and claim.payload["scopeDocumented"] is True
        and claim.payload["signoffAssigned"] is True
        and is_attestation_actor(claim.actor_type)
    )


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


def _data_retention_schedule_attestation(claim) -> bool:
    return (
        claim.payload["scheduleDefined"] is True
        and claim.payload["exceptionHandlingDefined"] is True
        and claim.payload["reviewWindowDays"] >= 1
        and is_attestation_actor(claim.actor_type)
    )


def _security_commitment_terms_attestation(claim) -> bool:
    return (
        claim.payload["termsPresent"] is True
        and claim.payload["agreementTypesCovered"] > 0
        and claim.payload["reviewWindowDays"] >= 1
        and is_attestation_actor(claim.actor_type)
    )


def _security_commitment_governance_attestation(claim) -> bool:
    return (
        bool(claim.payload["ownerRole"])
        and claim.payload["exceptionHandlingDefined"] is True
        and claim.payload["reviewWindowDays"] >= 1
        and is_attestation_actor(claim.actor_type)
    )


def _outsourced_development_requirement_attestation(claim) -> bool:
    return (
        claim.payload["requirementsDefined"] is True
        and claim.payload["relationshipScopeCount"] > 0
        and claim.payload["reviewWindowDays"] >= 1
        and is_attestation_actor(claim.actor_type)
    )


def _outsourced_development_review_attestation(claim) -> bool:
    return (
        claim.payload["oversightReviewPerformed"] is True
        and claim.payload["exceptionHandlingDefined"] is True
        and claim.payload["reviewWindowDays"] >= 1
        and is_attestation_actor(claim.actor_type)
    )


def _security_concern_intake_attestation(claim) -> bool:
    return (
        claim.payload["intakePathDefined"] is True
        and bool(claim.payload["ownerRole"])
        and claim.payload["reviewWindowDays"] >= 1
        and is_attestation_actor(claim.actor_type)
    )


def _security_concern_resolution_attestation(claim) -> bool:
    return (
        claim.payload["resolutionTrackingCurrent"] is True
        and claim.payload["ownersAssigned"] is True
        and claim.payload["reviewWindowDays"] >= 1
        and is_attestation_actor(claim.actor_type)
    )


def _remote_working_attestation(claim) -> bool:
    return (
        claim.payload["procedureCurrent"] is True
        and claim.payload["incidentReportingCovered"] is True
        and claim.payload["reviewWindowDays"] >= 1
        and is_attestation_actor(claim.actor_type)
    )


def _compliance_requirement_register_attestation(claim) -> bool:
    return (
        claim.payload["registerCurrent"] is True
        and claim.payload["requirementClassesCovered"] > 0
        and claim.payload["reviewWindowDays"] >= 1
        and is_attestation_actor(claim.actor_type)
    )


def _compliance_requirement_review_attestation(claim) -> bool:
    return (
        claim.payload["reviewCurrent"] is True
        and bool(claim.payload["ownerRole"])
        and claim.payload["reviewWindowDays"] >= 1
        and is_attestation_actor(claim.actor_type)
    )


def _isms_stakeholder_register_attestation(claim) -> bool:
    return (
        claim.payload["registerCurrent"] is True
        and claim.payload["stakeholderGroupsCovered"] > 0
        and claim.payload["reviewWindowDays"] >= 1
        and is_attestation_actor(claim.actor_type)
    )


def _isms_stakeholder_obligation_attestation(claim) -> bool:
    return (
        claim.payload["obligationsCurrent"] is True
        and bool(claim.payload["ownerRole"])
        and claim.payload["reviewWindowDays"] >= 1
        and is_attestation_actor(claim.actor_type)
    )


def _project_security_requirement_attestation(claim) -> bool:
    return (
        claim.payload["requirementsDefined"] is True
        and claim.payload["projectTypesCovered"] > 0
        and claim.payload["reviewWindowDays"] >= 1
        and is_attestation_actor(claim.actor_type)
    )


def _project_security_review_attestation(claim) -> bool:
    return (
        claim.payload["reviewPerformed"] is True
        and claim.payload["exceptionsTracked"] is True
        and claim.payload["reviewWindowDays"] >= 1
        and is_attestation_actor(claim.actor_type)
    )


def _customer_support_channel_attestation(claim) -> bool:
    return (
        claim.payload["channelsDocumented"] > 0
        and claim.payload["channelsReachable"] is True
        and claim.payload["reviewWindowDays"] >= 1
        and is_attestation_actor(claim.actor_type)
    )


def _customer_support_governance_attestation(claim) -> bool:
    return (
        claim.payload["escalationOwnershipDefined"] is True
        and claim.payload["staffingModelCurrent"] is True
        and claim.payload["reviewWindowDays"] >= 1
        and is_attestation_actor(claim.actor_type)
    )


def _intellectual_property_policy_attestation(claim) -> bool:
    return (
        claim.payload["policyCurrent"] is True
        and claim.payload["obligationClassesCovered"] > 0
        and claim.payload["reviewWindowDays"] >= 1
        and is_attestation_actor(claim.actor_type)
    )


def _intellectual_property_issue_attestation(claim) -> bool:
    return (
        claim.payload["handlingRulesCurrent"] is True
        and bool(claim.payload["ownerRole"])
        and claim.payload["reviewWindowDays"] >= 1
        and is_attestation_actor(claim.actor_type)
    )


def _corrective_action_process_attestation(claim) -> bool:
    return (
        claim.payload["processDefined"] is True
        and bool(claim.payload["ownerRole"])
        and claim.payload["reviewWindowDays"] >= 1
        and is_attestation_actor(claim.actor_type)
    )


def _corrective_action_followup_attestation(claim) -> bool:
    return (
        claim.payload["followupCurrent"] is True
        and claim.payload["ownersAssigned"] is True
        and claim.payload["reviewWindowDays"] >= 1
        and is_attestation_actor(claim.actor_type)
    )


def _code_of_conduct_attestation(claim) -> bool:
    return (
        claim.payload["acknowledgementsCurrent"] is True
        and claim.payload["populationScope"] in {"employees", "contractors", "mixed"}
        and claim.payload["reviewWindowDays"] >= 1
        and is_attestation_actor(claim.actor_type)
    )


def _conduct_governance_attestation(claim) -> bool:
    return (
        claim.payload["disciplinaryPathDefined"] is True
        and claim.payload["populationScope"] in {"employees", "contractors", "mixed"}
        and claim.payload["refreshTriggersDefined"] is True
        and claim.payload["reviewWindowDays"] >= 1
        and is_attestation_actor(claim.actor_type)
    )


def _disciplinary_policy_attestation(claim) -> bool:
    return (
        claim.payload["policyCurrent"] is True
        and claim.payload["populationsCovered"] >= 1
        and claim.payload["reviewWindowDays"] >= 1
        and is_attestation_actor(claim.actor_type)
    )


def _disciplinary_action_attestation(claim) -> bool:
    return (
        claim.payload["actionRecordsCurrent"] is True
        and claim.payload["reviewedBreachesCount"] >= 0
        and claim.payload["reviewWindowDays"] >= 1
        and is_attestation_actor(claim.actor_type)
    )


def _internal_audit_program_attestation(claim) -> bool:
    return (
        claim.payload["programCurrent"] is True
        and claim.payload["scheduleDefined"] is True
        and claim.payload["reviewWindowDays"] >= 1
        and is_attestation_actor(claim.actor_type)
    )


def _internal_audit_execution_attestation(claim) -> bool:
    return (
        claim.payload["findingsTracked"] is True
        and claim.payload["followUpCurrent"] is True
        and claim.payload["reviewWindowDays"] >= 1
        and is_attestation_actor(claim.actor_type)
    )


def _clear_desk_screen_policy_attestation(claim) -> bool:
    return (
        claim.payload["policyCurrent"] is True
        and claim.payload["workspaceTypesCovered"] >= 1
        and claim.payload["reviewWindowDays"] >= 1
        and is_attestation_actor(claim.actor_type)
    )


def _clear_desk_screen_coverage_attestation(claim) -> bool:
    return (
        claim.payload["areasCovered"] >= 1
        and claim.payload["communicationCurrent"] is True
        and claim.payload["reviewWindowDays"] >= 1
        and is_attestation_actor(claim.actor_type)
    )


def _security_community_membership_attestation(claim) -> bool:
    return (
        claim.payload["groupsCovered"] >= 1
        and claim.payload["participationCurrent"] is True
        and claim.payload["reviewWindowDays"] >= 1
        and is_attestation_actor(claim.actor_type)
    )


def _security_community_output_review_attestation(claim) -> bool:
    return (
        claim.payload["disseminationPathDefined"] is True
        and claim.payload["ownerDefined"] is True
        and claim.payload["reviewWindowDays"] >= 1
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


def _ai_human_review_trigger_attestation(claim) -> bool:
    return (
        claim.payload["highImpactTriggerCriteriaDocumented"] is True
        and claim.payload["humanReviewOwnerAssigned"] is True
        and claim.payload["contestPathDocumented"] is True
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


def _ai_task_envelope_state(claim) -> bool:
    return (
        claim.payload["purposeDeclared"] is True
        and claim.payload["allowedToolClassesDeclared"] is True
        and claim.payload["allowedDataClassesDeclared"] is True
        and claim.payload["retentionClassDeclared"] is True
        and claim.payload["humanReviewLinkagePresent"] is True
    )


def _ai_rights_ready_run_trace_state(claim) -> bool:
    return (
        claim.payload["traceRetentionEnabled"] is True
        and claim.payload["requestPurposeCaptured"] is True
        and claim.payload["inputClassificationsCaptured"] is True
        and claim.payload["outputReferencesCaptured"] is True
        and claim.payload["humanReviewLinkagePresent"] is True
    )


def _ai_supplier_transfer_attestation(claim) -> bool:
    return (
        claim.payload["supplierRegisterCurrent"] is True
        and claim.payload["subprocessorRolesDeclared"] is True
        and claim.payload["transferMechanismDeclared"] is True
        and is_attestation_actor(claim.actor_type)
    )


def _privacy_notice_publication_state(claim) -> bool:
    return (
        claim.payload["noticePublished"] is True
        and claim.payload["categoriesAndPurposesListed"] is True
        and claim.payload["rightsProcessLinked"] is True
        and claim.payload["noticeUrlReachable"] is True
        and claim.payload["reviewWindowDays"] >= 1
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
        "Keep privacy-by-design and automated-decision adequacy explicit as judgment rather than flattening them into a green check.",
        "Add live privacy-request execution metrics, notice publication checks, and processor-transfer evidence so more of the privacy corridor can move from documentary status toward operational replay.",
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
            claim_id="EX-CLAIM-111A",
            title="The lawful-basis register is current and records purpose boundaries for the in-scope personal-data processing.",
            route="attestation",
            expected_claim_type="lawful_basis_register_attestation",
            control_refs=["oc.privacy-03"],
            default_framework_mappings=[
                FrameworkMapping("GDPR", "lawful_basis_and_purpose_limitation", "gdpr.family.lawful_basis_and_purpose_limitation"),
                FrameworkMapping(
                    "UK ICO AI and data protection guidance",
                    "lawfulness_and_purpose_governance",
                    "ico_ai_guidance.family.lawfulness_and_purpose_governance",
                ),
                FrameworkMapping("ISO/IEC 42005", "impact_assessment_inputs", "iso_iec_42005.family.impact_assessment_inputs"),
            ],
            basis_when_present="The lawful-basis register claim is a signed synthetic attestation by the privacy manager.",
            basis_when_missing="No typed lawful-basis register attestation is attached to this synthetic corridor.",
            predicate=_lawful_basis_register_attestation,
            classification_rationale="Lawful-basis and purpose-register evidence remains documentary governance evidence in the current corridor.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-111B",
            title="The external privacy notice is published and links people to the current rights-handling path.",
            route="attestation",
            expected_claim_type="privacy_notice_attestation",
            control_refs=["oc.privacy-04"],
            default_framework_mappings=[
                FrameworkMapping("GDPR", "transparency_and_notices", "gdpr.family.transparency_and_notices"),
                FrameworkMapping(
                    "HIPAA Privacy Rule",
                    "notice_of_privacy_practices",
                    "hipaa_privacy_rule.family.notice_of_privacy_practices",
                ),
                FrameworkMapping(
                    "CCPA/CPRA",
                    "notice_at_collection_and_privacy_policy",
                    "ccpa_cpra.family.notice_at_collection_and_privacy_policy",
                ),
            ],
            basis_when_present="The privacy-notice claim is a signed synthetic attestation covering publication, purpose disclosure, and rights-contact linking.",
            basis_when_missing="No typed privacy-notice attestation is attached to this synthetic corridor.",
            predicate=_privacy_notice_attestation,
            classification_rationale="Public notice and rights-contact evidence remains documentary rather than a theorem.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-111C",
            title="A current privacy impact assessment exists for the in-scope product and names a sign-off owner.",
            route="attestation",
            expected_claim_type="privacy_impact_assessment_attestation",
            control_refs=["oc.privacy-05"],
            default_framework_mappings=[
                FrameworkMapping("GDPR", "privacy_impact_assessment", "gdpr.family.privacy_impact_assessment"),
                FrameworkMapping(
                    "UK ICO AI and data protection guidance",
                    "data_protection_impact_assessment",
                    "ico_ai_guidance.family.data_protection_impact_assessment",
                ),
                FrameworkMapping("ISO/IEC 42005", "impact_assessment_process", "iso_iec_42005.family.impact_assessment_process"),
            ],
            basis_when_present="The privacy-impact claim is a signed synthetic attestation covering scope, current review, and named sign-off ownership.",
            basis_when_missing="No typed privacy impact assessment attestation is attached to this synthetic corridor.",
            predicate=_privacy_impact_assessment_attestation,
            classification_rationale="Impact-assessment evidence remains documentary governance evidence in the public corridor.",
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
        VerificationItemSpec(
            claim_id="EX-CLAIM-134",
            title="Data retention schedules and exception handling are documented and current for the scoped lifecycle program.",
            route="attestation",
            expected_claim_type="data_retention_schedule_attestation",
            control_refs=["oc.data-05"],
            default_framework_mappings=[],
            basis_when_present="The retention-schedule claim is a signed synthetic attestation by the named privacy delegate.",
            basis_when_missing="No typed retention-schedule attestation is attached to this synthetic corridor.",
            predicate=_data_retention_schedule_attestation,
            classification_rationale="Retention schedules remain documentary governance evidence even when individual deletion events are outside the current proof corridor.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-135",
            title="Retention periods, exception scope, and deletion adequacy are sufficient for the in-scope data lifecycle surface.",
            route="judgment",
            expected_claim_type=None,
            control_refs=["oc.data-06"],
            default_framework_mappings=[
                FrameworkMapping("ISO 27001", "data_retention_and_deletion", "iso27001.family.data_retention_and_deletion"),
                FrameworkMapping("SOC 2", "data_retention_and_deletion", "soc2.family.data_retention_and_deletion"),
                FrameworkMapping("GDPR", "storage_limitation_and_erasure", "gdpr.family.storage_limitation_and_erasure"),
                FrameworkMapping("CCPA/CPRA", "retention_and_deletion_governance", "ccpa_cpra.family.retention_and_deletion_governance"),
            ],
            basis_when_present=None,
            basis_when_missing="This remains a human adequacy zone. The public corridor does not pretend to prove that retention periods, exceptions, or deletion behaviour are sufficient across every holder and downstream copy.",
            predicate=None,
            classification_rationale="Retention and deletion adequacy stays explicitly judgment-routed even when narrower schedule attestations are structured.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-136",
            title="Scoped service and supplier agreements carry the declared security commitment terms for the current review window.",
            route="attestation",
            expected_claim_type="security_commitment_terms_attestation",
            control_refs=["oc.vendor-07"],
            default_framework_mappings=[],
            basis_when_present="The security-commitment-terms claim is a signed synthetic attestation by the named vendor-risk delegate.",
            basis_when_missing="No typed security-commitment-terms attestation is attached to this synthetic corridor.",
            predicate=_security_commitment_terms_attestation,
            classification_rationale="Agreement-term presence is a documentary slice and should stay separate from the wider adequacy judgment about those commitments.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-137",
            title="Ownership, review cadence, and exception handling are current for scoped security commitment governance.",
            route="attestation",
            expected_claim_type="security_commitment_governance_attestation",
            control_refs=["oc.vendor-08"],
            default_framework_mappings=[],
            basis_when_present="The security-commitment-governance claim is a signed synthetic attestation by the named vendor-risk delegate.",
            basis_when_missing="No typed security-commitment-governance attestation is attached to this synthetic corridor.",
            predicate=_security_commitment_governance_attestation,
            classification_rationale="Governance over supplier security commitments remains documentary and owner-attested in the current corridor.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-138",
            title="The scoped security commitments and their governance are adequate for the supplier and transfer risks in scope.",
            route="judgment",
            expected_claim_type=None,
            control_refs=["oc.vendor-09"],
            default_framework_mappings=[
                FrameworkMapping("SOC 2", "vendor_management", "soc2.family.vendor_management"),
                FrameworkMapping("ISO 27001", "supplier_relationships", "iso27001.family.supplier_relationships"),
            ],
            basis_when_present=None,
            basis_when_missing="This remains a human adequacy zone. The public corridor does not pretend to prove that the scoped security commitments and review model are sufficient for all supplier risks in scope.",
            predicate=None,
            classification_rationale="Supplier security-commitment adequacy stays judgment-routed even when narrower terms and governance facts are structured.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-139",
            title="Outsourced development relationships carry current security requirements for the declared review window.",
            route="attestation",
            expected_claim_type="outsourced_development_requirement_attestation",
            control_refs=["oc.vendor-10"],
            default_framework_mappings=[],
            basis_when_present="The outsourced-development-requirements claim is a signed synthetic attestation by the named vendor-risk delegate.",
            basis_when_missing="No typed outsourced-development-requirements attestation is attached to this synthetic corridor.",
            predicate=_outsourced_development_requirement_attestation,
            classification_rationale="Supplier-development requirement presence remains documentary governance evidence rather than a theorem about delivery behaviour.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-140",
            title="Oversight and exception handling are current for scoped outsourced development relationships.",
            route="attestation",
            expected_claim_type="outsourced_development_review_attestation",
            control_refs=["oc.vendor-11"],
            default_framework_mappings=[],
            basis_when_present="The outsourced-development-review claim is a signed synthetic attestation by the named vendor-risk delegate.",
            basis_when_missing="No typed outsourced-development-review attestation is attached to this synthetic corridor.",
            predicate=_outsourced_development_review_attestation,
            classification_rationale="Outsourced-development oversight stays attestation-routed because the current public corridor captures governance records, not full supplier-performance proofs.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-141",
            title="The outsourced development model is adequate for the scoped third-party delivery risks.",
            route="judgment",
            expected_claim_type=None,
            control_refs=["oc.vendor-12"],
            default_framework_mappings=[
                FrameworkMapping("SOC 2", "vendor_management", "soc2.family.vendor_management"),
            ],
            basis_when_present=None,
            basis_when_missing="This remains a human adequacy zone. The public corridor does not pretend to prove that outsourced development controls are sufficient for every supplier or delivery path in scope.",
            predicate=None,
            classification_rationale="Outsourced-development adequacy stays explicitly judgment-routed even when requirement and oversight records are structured.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-142",
            title="A current intake path exists for reported security concerns relevant to the scoped service operations.",
            route="attestation",
            expected_claim_type="security_concern_intake_attestation",
            control_refs=["oc.ir-04"],
            default_framework_mappings=[],
            basis_when_present="The security-concern-intake claim is a signed synthetic attestation by the named incident-response delegate.",
            basis_when_missing="No typed security-concern-intake attestation is attached to this synthetic corridor.",
            predicate=_security_concern_intake_attestation,
            classification_rationale="Concern intake remains documentary governance evidence and should stay separate from broader adequacy judgments about handling quality.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-143",
            title="Tracking, ownership, and resolution follow-up are current for the scoped security-concern process.",
            route="attestation",
            expected_claim_type="security_concern_resolution_attestation",
            control_refs=["oc.ir-05"],
            default_framework_mappings=[],
            basis_when_present="The security-concern-resolution claim is a signed synthetic attestation by the named incident-response delegate.",
            basis_when_missing="No typed security-concern-resolution attestation is attached to this synthetic corridor.",
            predicate=_security_concern_resolution_attestation,
            classification_rationale="Follow-up handling for reported concerns remains documentary governance evidence in the current corridor.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-144",
            title="The scoped handling model for reported security concerns is adequate to triage, resolve, and learn from the issues that matter.",
            route="judgment",
            expected_claim_type=None,
            control_refs=["oc.ir-06"],
            default_framework_mappings=[
                FrameworkMapping("SOC 2", "incident_response", "soc2.family.incident_response"),
            ],
            basis_when_present=None,
            basis_when_missing="This remains a human adequacy zone. The public corridor does not pretend to prove that the scoped concern-handling model is sufficient for every issue type or severity.",
            predicate=None,
            classification_rationale="Security-concern handling adequacy stays judgment-routed even when narrower intake and follow-up facts are structured.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-145",
            title="Scoped remote access traverses the declared remote-access path with device posture controls bounded for the systems in scope.",
            route="decidable",
            expected_claim_type="remote_access_posture_state",
            control_refs=["oc.remote-01"],
            default_framework_mappings=[],
            basis_when_present="The remote-access export shows a declared remote path, bounded device posture, and a positive scoped system count.",
            basis_when_missing="No typed remote-access posture export is attached to this synthetic corridor.",
            basis_when_failed="The remote-access posture export was present but did not satisfy the narrow declared-path and device-posture predicate.",
            predicate=_remote_access_posture_state,
            classification_rationale="Deterministic remote-access boundary state over a narrow declared-path and device-posture predicate.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-146",
            title="A current remote-working procedure covers incident reporting for the scoped workforce and review window.",
            route="attestation",
            expected_claim_type="remote_working_attestation",
            control_refs=["oc.remote-02"],
            default_framework_mappings=[],
            basis_when_present="The remote-working procedure claim is a signed synthetic attestation by the named remote-work owner.",
            basis_when_missing="No typed remote-working attestation is attached to this synthetic corridor.",
            predicate=_remote_working_attestation,
            classification_rationale="Remote-working procedure evidence remains documentary and owner-attested in the current corridor.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-147",
            title="The scoped remote-working model is adequate for the device, workspace, and incident-reporting risks that matter.",
            route="judgment",
            expected_claim_type=None,
            control_refs=["oc.remote-03"],
            default_framework_mappings=[
                FrameworkMapping("ISO 27001", "remote_working", "iso27001.family.remote_working"),
            ],
            basis_when_present=None,
            basis_when_missing="This remains a human adequacy zone. The public corridor does not pretend to prove that the scoped remote-working model is sufficient for every remote-work risk in scope.",
            predicate=None,
            classification_rationale="Remote-working adequacy stays explicitly judgment-routed even when narrower posture and procedure facts are structured.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-148",
            title="A current register of legal, regulatory, contractual, and compliance requirements is attested for the scoped ISMS surface.",
            route="attestation",
            expected_claim_type="compliance_requirement_register_attestation",
            control_refs=["oc.cpl-01"],
            default_framework_mappings=[],
            basis_when_present="The compliance-requirement register claim is a signed synthetic attestation by the named compliance owner.",
            basis_when_missing="No typed compliance-requirement register attestation is attached to this synthetic corridor.",
            predicate=_compliance_requirement_register_attestation,
            classification_rationale="Compliance-inventory presence remains documentary governance evidence in the current corridor.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-149",
            title="Compliance requirement review cadence, ownership, and update handling are current for the scoped inventory.",
            route="attestation",
            expected_claim_type="compliance_requirement_review_attestation",
            control_refs=["oc.cpl-02"],
            default_framework_mappings=[],
            basis_when_present="The compliance-requirement review claim is a signed synthetic attestation by the named compliance owner.",
            basis_when_missing="No typed compliance-requirement review attestation is attached to this synthetic corridor.",
            predicate=_compliance_requirement_review_attestation,
            classification_rationale="Compliance-review governance remains documentary and owner-attested in the current corridor.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-150",
            title="The scoped compliance inventory is adequate for the legal, regulatory, and contractual obligations that materially affect the ISMS.",
            route="judgment",
            expected_claim_type=None,
            control_refs=["oc.cpl-03"],
            default_framework_mappings=[
                FrameworkMapping("ISO 27001", "compliance_requirements", "iso27001.family.compliance_requirements"),
            ],
            basis_when_present=None,
            basis_when_missing="This remains a human adequacy zone. The public corridor does not pretend to prove that the scoped compliance inventory is complete or sufficient for every downstream mapping and audit need.",
            predicate=None,
            classification_rationale="Compliance-inventory adequacy stays explicitly judgment-routed even when narrower register and review facts are structured.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-151",
            title="A current register of interested parties and stakeholder groups is attested for the scoped ISMS surface.",
            route="attestation",
            expected_claim_type="isms_stakeholder_register_attestation",
            control_refs=["oc.gov-33"],
            default_framework_mappings=[],
            basis_when_present="The stakeholder-register claim is a signed synthetic attestation by the named ISMS owner.",
            basis_when_missing="No typed stakeholder-register attestation is attached to this synthetic corridor.",
            predicate=_isms_stakeholder_register_attestation,
            classification_rationale="Stakeholder inventory evidence remains documentary governance evidence in the current corridor.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-152",
            title="Stakeholder expectations, obligations, and review ownership are current for the scoped ISMS surface.",
            route="attestation",
            expected_claim_type="isms_stakeholder_obligation_attestation",
            control_refs=["oc.gov-34"],
            default_framework_mappings=[],
            basis_when_present="The stakeholder-obligations claim is a signed synthetic attestation by the named ISMS owner.",
            basis_when_missing="No typed stakeholder-obligations attestation is attached to this synthetic corridor.",
            predicate=_isms_stakeholder_obligation_attestation,
            classification_rationale="Stakeholder obligation evidence remains documentary and owner-attested in the current corridor.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-153",
            title="The scoped stakeholder-management model is adequate for the interested parties and expectations that materially affect the ISMS.",
            route="judgment",
            expected_claim_type=None,
            control_refs=["oc.gov-35"],
            default_framework_mappings=[
                FrameworkMapping("ISO 27001", "isms_stakeholder_management", "iso27001.family.isms_stakeholder_management"),
            ],
            basis_when_present=None,
            basis_when_missing="This remains a human adequacy zone. The public corridor does not pretend to prove that the scoped stakeholder model is complete or sufficient for every governance obligation.",
            predicate=None,
            classification_rationale="Stakeholder-management adequacy stays judgment-routed even when narrower register and obligation facts are structured.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-154",
            title="Current project-security requirements are defined for the project types in the scoped delivery portfolio.",
            route="attestation",
            expected_claim_type="project_security_requirement_attestation",
            control_refs=["oc.proj-01"],
            default_framework_mappings=[],
            basis_when_present="The project-security requirements claim is a signed synthetic attestation by the named project-security owner.",
            basis_when_missing="No typed project-security requirements attestation is attached to this synthetic corridor.",
            predicate=_project_security_requirement_attestation,
            classification_rationale="Project-security requirements remain documentary governance evidence in the current corridor.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-155",
            title="Project-security review and exception tracking are current for the scoped delivery portfolio.",
            route="attestation",
            expected_claim_type="project_security_review_attestation",
            control_refs=["oc.proj-02"],
            default_framework_mappings=[],
            basis_when_present="The project-security review claim is a signed synthetic attestation by the named project-security owner.",
            basis_when_missing="No typed project-security review attestation is attached to this synthetic corridor.",
            predicate=_project_security_review_attestation,
            classification_rationale="Project-security review evidence remains documentary and owner-attested in the current corridor.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-156",
            title="The scoped project-security model is adequate for integrating security into the project types and lifecycle stages that matter.",
            route="judgment",
            expected_claim_type=None,
            control_refs=["oc.proj-03"],
            default_framework_mappings=[
                FrameworkMapping("ISO 27001", "project_security", "iso27001.family.project_security"),
            ],
            basis_when_present=None,
            basis_when_missing="This remains a human adequacy zone. The public corridor does not pretend to prove that the scoped project-security model is complete or sufficient for every delivery risk in scope.",
            predicate=None,
            classification_rationale="Project-security adequacy stays judgment-routed even when narrower requirements and review facts are structured.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-157",
            title="Current customer support channels are documented and reachable for the scoped service surface.",
            route="attestation",
            expected_claim_type="customer_support_channel_attestation",
            control_refs=["oc.ops-04"],
            default_framework_mappings=[],
            basis_when_present="The customer-support-channel claim is a signed synthetic attestation by the named customer-support owner.",
            basis_when_missing="No typed customer-support-channel attestation is attached to this synthetic corridor.",
            predicate=_customer_support_channel_attestation,
            classification_rationale="Customer-support channel evidence remains documentary and owner-attested in the current corridor.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-158",
            title="Support staffing, escalation ownership, and response governance are current for the scoped service surface.",
            route="attestation",
            expected_claim_type="customer_support_governance_attestation",
            control_refs=["oc.ops-05"],
            default_framework_mappings=[],
            basis_when_present="The customer-support-governance claim is a signed synthetic attestation by the named customer-support owner.",
            basis_when_missing="No typed customer-support-governance attestation is attached to this synthetic corridor.",
            predicate=_customer_support_governance_attestation,
            classification_rationale="Customer-support governance remains documentary and owner-attested in the current corridor.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-159",
            title="The scoped customer-support model is adequate for the channel, escalation, and service risks that matter.",
            route="judgment",
            expected_claim_type=None,
            control_refs=["oc.ops-06"],
            default_framework_mappings=[
                FrameworkMapping("SOC 2", "customer_support_operations", "soc2.family.customer_support_operations"),
            ],
            basis_when_present=None,
            basis_when_missing="This remains a human adequacy zone. The public corridor does not pretend to prove that the scoped customer-support model is sufficient for every service or incident scenario.",
            predicate=None,
            classification_rationale="Customer-support adequacy stays judgment-routed even when narrower channel and governance facts are structured.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-160",
            title="A current intellectual-property policy or requirement set is attested for the scoped service and workforce surface.",
            route="attestation",
            expected_claim_type="intellectual_property_policy_attestation",
            control_refs=["oc.gov-39"],
            default_framework_mappings=[],
            basis_when_present="The intellectual-property policy claim is a signed synthetic attestation by the named ethics owner.",
            basis_when_missing="No typed intellectual-property policy attestation is attached to this synthetic corridor.",
            predicate=_intellectual_property_policy_attestation,
            classification_rationale="Intellectual-property policy evidence remains documentary governance evidence in the current corridor.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-161",
            title="Issue tracking, handling rules, and ownership are current for scoped intellectual-property obligations.",
            route="attestation",
            expected_claim_type="intellectual_property_issue_attestation",
            control_refs=["oc.gov-40"],
            default_framework_mappings=[],
            basis_when_present="The intellectual-property issue-handling claim is a signed synthetic attestation by the named ethics owner.",
            basis_when_missing="No typed intellectual-property issue-handling attestation is attached to this synthetic corridor.",
            predicate=_intellectual_property_issue_attestation,
            classification_rationale="Intellectual-property issue handling remains documentary and owner-attested in the current corridor.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-162",
            title="The scoped intellectual-property posture is adequate to protect proprietary material and avoid misuse of third-party rights in scope.",
            route="judgment",
            expected_claim_type=None,
            control_refs=["oc.gov-41"],
            default_framework_mappings=[
                FrameworkMapping("ISO 27001", "intellectual_property_rights", "iso27001.family.intellectual_property_rights"),
                FrameworkMapping("SOC 2", "ethics_and_integrity", "soc2.family.ethics_and_integrity"),
            ],
            basis_when_present=None,
            basis_when_missing="This remains a human adequacy zone. The public corridor does not pretend to prove that the scoped intellectual-property posture is complete or sufficient for every rights scenario.",
            predicate=None,
            classification_rationale="Intellectual-property adequacy stays judgment-routed even when narrower policy and issue-handling facts are structured.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-163",
            title="A current corrective-action process is defined with named ownership for the scoped ISMS improvement cycle.",
            route="attestation",
            expected_claim_type="corrective_action_process_attestation",
            control_refs=["oc.gov-36"],
            default_framework_mappings=[],
            basis_when_present="The corrective-action-process claim is a signed synthetic attestation by the named ISMS owner.",
            basis_when_missing="No typed corrective-action-process attestation is attached to this synthetic corridor.",
            predicate=_corrective_action_process_attestation,
            classification_rationale="Corrective-action process evidence remains documentary and owner-attested in the current corridor.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-164",
            title="Corrective-action follow-up and remediation ownership are current for the scoped improvement cycle.",
            route="attestation",
            expected_claim_type="corrective_action_followup_attestation",
            control_refs=["oc.gov-37"],
            default_framework_mappings=[],
            basis_when_present="The corrective-action-follow-up claim is a signed synthetic attestation by the named ISMS owner.",
            basis_when_missing="No typed corrective-action-follow-up attestation is attached to this synthetic corridor.",
            predicate=_corrective_action_followup_attestation,
            classification_rationale="Corrective-action follow-up remains documentary and owner-attested in the current corridor.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-165",
            title="The scoped continual-improvement model is adequate to identify, prioritize, and close the issues that matter.",
            route="judgment",
            expected_claim_type=None,
            control_refs=["oc.gov-38"],
            default_framework_mappings=[
                FrameworkMapping(
                    "ISO 27001",
                    "continual_improvement_and_corrective_action",
                    "iso27001.family.continual_improvement_and_corrective_action",
                ),
            ],
            basis_when_present=None,
            basis_when_missing="This remains a human adequacy zone. The public corridor does not pretend to prove that the scoped corrective-action model is sufficient for every issue class or improvement cycle.",
            predicate=None,
            classification_rationale="Continual-improvement adequacy stays judgment-routed even when narrower process and follow-up facts are structured.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-166",
            title="A current code-of-conduct acknowledgement set exists for the scoped workforce population.",
            route="attestation",
            expected_claim_type="code_of_conduct_attestation",
            control_refs=["oc.conduct-01"],
            default_framework_mappings=[],
            basis_when_present="The code-of-conduct claim is a signed synthetic attestation by the named ethics owner.",
            basis_when_missing="No typed code-of-conduct attestation is attached to this synthetic corridor.",
            predicate=_code_of_conduct_attestation,
            classification_rationale="Workforce conduct acknowledgement evidence remains documentary and owner-attested in the current corridor.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-167",
            title="Refresh triggers and disciplinary pathways are current for the scoped workforce conduct program.",
            route="attestation",
            expected_claim_type="conduct_governance_attestation",
            control_refs=["oc.conduct-02"],
            default_framework_mappings=[],
            basis_when_present="The conduct-governance claim is a signed synthetic attestation by the named ethics owner.",
            basis_when_missing="No typed conduct-governance attestation is attached to this synthetic corridor.",
            predicate=_conduct_governance_attestation,
            classification_rationale="Conduct governance remains documentary and owner-attested in the current corridor.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-168",
            title="The scoped workforce conduct model is adequate for the behavioural and security risks that matter.",
            route="judgment",
            expected_claim_type=None,
            control_refs=["oc.conduct-03"],
            default_framework_mappings=[
                FrameworkMapping(
                    "ISO 27001",
                    "workforce_conduct",
                    "iso27001.family.workforce_conduct",
                ),
            ],
            basis_when_present=None,
            basis_when_missing="This remains a human adequacy zone. The public corridor does not pretend to prove that the scoped conduct model is sufficient for every behavioural, legal, or security scenario.",
            predicate=None,
            classification_rationale="Workforce conduct adequacy stays judgment-routed even when acknowledgement and governance facts are structured.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-169",
            title="A current disciplinary policy covers the scoped workforce populations.",
            route="attestation",
            expected_claim_type="disciplinary_policy_attestation",
            control_refs=["oc.hr-13"],
            default_framework_mappings=[],
            basis_when_present="The disciplinary-policy claim is a signed synthetic attestation by the named ethics owner.",
            basis_when_missing="No typed disciplinary-policy attestation is attached to this synthetic corridor.",
            predicate=_disciplinary_policy_attestation,
            classification_rationale="Disciplinary policy evidence remains documentary and owner-attested in the current corridor.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-170",
            title="Disciplinary action records are current for the scoped breach-review window.",
            route="attestation",
            expected_claim_type="disciplinary_action_attestation",
            control_refs=["oc.hr-14"],
            default_framework_mappings=[],
            basis_when_present="The disciplinary-action claim is a signed synthetic attestation by the named ethics owner.",
            basis_when_missing="No typed disciplinary-action attestation is attached to this synthetic corridor.",
            predicate=_disciplinary_action_attestation,
            classification_rationale="Disciplinary action records remain documentary and owner-attested in the current corridor.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-171",
            title="The scoped disciplinary model is adequate to respond proportionately and consistently when relevant breaches occur.",
            route="judgment",
            expected_claim_type=None,
            control_refs=["oc.hr-15"],
            default_framework_mappings=[
                FrameworkMapping(
                    "ISO 27001",
                    "disciplinary_process",
                    "iso27001.family.disciplinary_process",
                ),
            ],
            basis_when_present=None,
            basis_when_missing="This remains a human adequacy zone. The public corridor does not pretend to prove that the scoped disciplinary model is timely, consistent, or sufficient for every breach scenario.",
            predicate=None,
            classification_rationale="Disciplinary adequacy stays judgment-routed even when narrower policy and action facts are structured.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-172",
            title="A current internal-audit program and schedule exist for the scoped control surface.",
            route="attestation",
            expected_claim_type="internal_audit_program_attestation",
            control_refs=["oc.audit-01"],
            default_framework_mappings=[],
            basis_when_present="The internal-audit-program claim is a signed synthetic attestation by the named compliance owner.",
            basis_when_missing="No typed internal-audit-program attestation is attached to this synthetic corridor.",
            predicate=_internal_audit_program_attestation,
            classification_rationale="Internal-audit program evidence remains documentary and owner-attested in the current corridor.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-173",
            title="Findings and follow-up are current for the scoped internal-audit cycle.",
            route="attestation",
            expected_claim_type="internal_audit_execution_attestation",
            control_refs=["oc.audit-02"],
            default_framework_mappings=[],
            basis_when_present="The internal-audit-execution claim is a signed synthetic attestation by the named compliance owner.",
            basis_when_missing="No typed internal-audit-execution attestation is attached to this synthetic corridor.",
            predicate=_internal_audit_execution_attestation,
            classification_rationale="Internal-audit execution evidence remains documentary and owner-attested in the current corridor.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-174",
            title="The scoped internal-audit model is adequate to provide independent, useful assurance over the controls that matter.",
            route="judgment",
            expected_claim_type=None,
            control_refs=["oc.audit-03"],
            default_framework_mappings=[
                FrameworkMapping(
                    "ISO 27001",
                    "internal_audit_program",
                    "iso27001.family.internal_audit_program",
                ),
            ],
            basis_when_present=None,
            basis_when_missing="This remains a human adequacy zone. The public corridor does not pretend to prove that the scoped internal-audit model is sufficiently independent or deep.",
            predicate=None,
            classification_rationale="Internal-audit adequacy stays judgment-routed even when narrower program and execution facts are structured.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-175",
            title="A current clear-desk and clear-screen policy exists for the scoped work areas.",
            route="attestation",
            expected_claim_type="clear_desk_screen_policy_attestation",
            control_refs=["oc.phys-01"],
            default_framework_mappings=[],
            basis_when_present="The clear-desk-screen policy claim is a signed synthetic attestation by the named remote-working owner.",
            basis_when_missing="No typed clear-desk-screen policy attestation is attached to this synthetic corridor.",
            predicate=_clear_desk_screen_policy_attestation,
            classification_rationale="Workspace-hygiene policy evidence remains documentary and owner-attested in the current corridor.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-176",
            title="Communication and coverage are current for the scoped clear-desk and clear-screen program.",
            route="attestation",
            expected_claim_type="clear_desk_screen_coverage_attestation",
            control_refs=["oc.phys-02"],
            default_framework_mappings=[],
            basis_when_present="The clear-desk-screen coverage claim is a signed synthetic attestation by the named remote-working owner.",
            basis_when_missing="No typed clear-desk-screen coverage attestation is attached to this synthetic corridor.",
            predicate=_clear_desk_screen_coverage_attestation,
            classification_rationale="Workspace-hygiene coverage remains documentary and owner-attested in the current corridor.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-177",
            title="The scoped workspace hygiene model is adequate to reduce inadvertent physical disclosure and shoulder-surfing risks.",
            route="judgment",
            expected_claim_type=None,
            control_refs=["oc.phys-03"],
            default_framework_mappings=[
                FrameworkMapping(
                    "ISO 27001",
                    "physical_workspace_hygiene",
                    "iso27001.family.physical_workspace_hygiene",
                ),
            ],
            basis_when_present=None,
            basis_when_missing="This remains a human adequacy zone. The public corridor does not pretend to prove that the scoped workspace-hygiene model is sufficient for every physical disclosure scenario.",
            predicate=None,
            classification_rationale="Workspace-hygiene adequacy stays judgment-routed even when narrower policy and coverage facts are structured.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-178",
            title="Current participation exists in the scoped external security or special-interest groups.",
            route="attestation",
            expected_claim_type="security_community_membership_attestation",
            control_refs=["oc.intel-01"],
            default_framework_mappings=[],
            basis_when_present="The security-community-membership claim is a signed synthetic attestation by the named project-security owner.",
            basis_when_missing="No typed security-community-membership attestation is attached to this synthetic corridor.",
            predicate=_security_community_membership_attestation,
            classification_rationale="External security-community participation remains documentary and owner-attested in the current corridor.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-179",
            title="Ownership and dissemination are current for scoped external security inputs.",
            route="attestation",
            expected_claim_type="security_community_output_review_attestation",
            control_refs=["oc.intel-02"],
            default_framework_mappings=[],
            basis_when_present="The security-community-output-review claim is a signed synthetic attestation by the named project-security owner.",
            basis_when_missing="No typed security-community-output-review attestation is attached to this synthetic corridor.",
            predicate=_security_community_output_review_attestation,
            classification_rationale="Security-community output handling remains documentary and owner-attested in the current corridor.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-180",
            title="The scoped security-community participation model is adequate to turn relevant external insights into useful internal action.",
            route="judgment",
            expected_claim_type=None,
            control_refs=["oc.intel-03"],
            default_framework_mappings=[
                FrameworkMapping(
                    "ISO 27001",
                    "security_community_participation",
                    "iso27001.family.security_community_participation",
                ),
            ],
            basis_when_present=None,
            basis_when_missing="This remains a human adequacy zone. The public corridor does not pretend to prove that the scoped participation model is frequent, relevant, or effective enough for every threat context.",
            predicate=None,
            classification_rationale="Security-community participation adequacy stays judgment-routed even when narrower membership and dissemination facts are structured.",
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
    bundle_scope_note="Synthetic public-safe ExampleCo proof bundle for a narrow AI governance corridor spanning documentary governance evidence, machine-checkable transparency and trace artifacts, supplier-transfer governance, and additional evaluation and data-governance attestations.",
    next_actions=[
        "Keep legal classification, prohibited-practice review, and the legality of significant-effect automated decisions outside the issued corridor unless they are explicitly modeled.",
        "Turn the typed task-envelope, rights-ready run-trace, supplier-transfer, and live notice-publication artifacts from synthetic examples into live operator-fed evidence and replayable production traces.",
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
        "- task-envelope, rights-ready run-trace, supplier-transfer, and notice-publication artifacts become explicit and replayable,",
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
        VerificationItemSpec(
            claim_id="EX-CLAIM-709",
            title="The lawful-basis and purpose register is current for the scoped AI-assisted processing path.",
            route="attestation",
            expected_claim_type="lawful_basis_register_attestation",
            control_refs=["oc.privacy-03"],
            default_framework_mappings=[
                FrameworkMapping("GDPR", "lawful_basis_and_purpose_limitation", "gdpr.family.lawful_basis_and_purpose_limitation"),
                FrameworkMapping(
                    "UK ICO AI and data protection guidance",
                    "lawfulness_and_purpose_governance",
                    "ico_ai_guidance.family.lawfulness_and_purpose_governance",
                ),
                FrameworkMapping("ISO/IEC 42005", "impact_assessment_inputs", "iso_iec_42005.family.impact_assessment_inputs"),
            ],
            basis_when_present="The lawful-basis register claim is a signed synthetic attestation covering purpose boundaries and assigned lawful basis for the scoped AI-assisted processing path.",
            basis_when_missing="No typed lawful-basis register attestation is attached to this AI governance corridor.",
            basis_when_failed="The lawful-basis register attestation was present but did not satisfy the current corridor predicate.",
            predicate=_lawful_basis_register_attestation,
            classification_rationale="Lawful-basis governance remains documentary but should still be explicit for AI-assisted processing.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-710",
            title="A current privacy or AI impact assessment exists for the scoped AI-assisted processing path.",
            route="attestation",
            expected_claim_type="privacy_impact_assessment_attestation",
            control_refs=["oc.privacy-05"],
            default_framework_mappings=[
                FrameworkMapping("GDPR", "privacy_impact_assessment", "gdpr.family.privacy_impact_assessment"),
                FrameworkMapping(
                    "UK ICO AI and data protection guidance",
                    "data_protection_impact_assessment",
                    "ico_ai_guidance.family.data_protection_impact_assessment",
                ),
                FrameworkMapping("ISO/IEC 42005", "impact_assessment_process", "iso_iec_42005.family.impact_assessment_process"),
            ],
            basis_when_present="The privacy-impact claim is a signed synthetic attestation covering a current scoped impact assessment and named sign-off ownership.",
            basis_when_missing="No typed privacy-impact-assessment attestation is attached to this AI governance corridor.",
            basis_when_failed="The privacy-impact-assessment attestation was present but did not satisfy the current corridor predicate.",
            predicate=_privacy_impact_assessment_attestation,
            classification_rationale="Impact-assessment evidence remains documentary governance evidence rather than proof.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-711",
            title="High-impact human review triggers and a contest path are documented for the scoped AI-assisted decision path.",
            route="attestation",
            expected_claim_type="ai_human_review_trigger_attestation",
            control_refs=["oc.ai-09"],
            default_framework_mappings=[
                FrameworkMapping("GDPR", "automated_decision_human_review", "gdpr.family.automated_decision_human_review"),
                FrameworkMapping(
                    "UK ICO AI and data protection guidance",
                    "human_review_and_contestability",
                    "ico_ai_guidance.family.human_review_and_contestability",
                ),
                FrameworkMapping("NIST AI RMF 1.0", "human_oversight_and_fallback", "nist_ai_rmf_1_0.family.human_oversight_and_fallback"),
                FrameworkMapping("ISO/IEC 42001", "human_oversight_and_response", "iso_iec_42001.family.human_oversight_and_response"),
                FrameworkMapping("ISO/IEC 42005", "human_review_and_impact_response", "iso_iec_42005.family.human_review_and_impact_response"),
            ],
            basis_when_present="The human-review-trigger claim is a signed synthetic attestation covering trigger criteria, assigned review ownership, and contestability routing.",
            basis_when_missing="No typed AI human-review-trigger attestation is attached to this AI governance corridor.",
            basis_when_failed="The AI human-review-trigger attestation was present but did not satisfy the current corridor predicate.",
            predicate=_ai_human_review_trigger_attestation,
            classification_rationale="Human-review trigger evidence remains documentary governance evidence in the current AI corridor.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-712",
            title="The legality and contestability of significant-effect automated decisions have been fully demonstrated for every in-scope use case.",
            route="judgment",
            expected_claim_type=None,
            control_refs=["oc.ai-10"],
            default_framework_mappings=[
                FrameworkMapping("GDPR", "automated_decision_and_rights_boundary", "gdpr.family.automated_decision_and_rights_boundary"),
                FrameworkMapping(
                    "UK ICO AI and data protection guidance",
                    "automated_decision_adequacy",
                    "ico_ai_guidance.family.automated_decision_adequacy",
                ),
            ],
            basis_when_present=None,
            basis_when_missing="This remains a human legal and product-adequacy zone that the public synthetic corridor does not reduce to a proof or attestation-only green check.",
            predicate=None,
            classification_rationale="The legality and sufficiency of high-impact automated-decision controls remain explicitly outside the machine-proof corridor.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-713",
            title="A typed task envelope bounds purpose, tool classes, data classes, retention class, and human-review linkage for the scoped AI-assisted operation.",
            route="decidable",
            expected_claim_type="ai_task_envelope_state",
            control_refs=["oc.ai-11"],
            default_framework_mappings=[],
            basis_when_present="The task-envelope export shows purpose, bounded tool classes, bounded data classes, retention class, and human-review linkage are all declared for the scoped AI-assisted operation.",
            basis_when_missing="No typed AI task-envelope export is attached to this AI governance corridor.",
            basis_when_failed="The AI task-envelope export was present but did not satisfy the narrow bounded-envelope predicate.",
            predicate=_ai_task_envelope_state,
            classification_rationale="A narrow task envelope is machine-checkable when the scoped AI operation publishes a typed control-plane envelope rather than only prose.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-714",
            title="A rights-ready run trace retains purpose, input classifications, output references, and human-review linkage for the scoped AI-assisted operation.",
            route="decidable",
            expected_claim_type="ai_rights_ready_run_trace_state",
            control_refs=["oc.ai-12"],
            default_framework_mappings=[],
            basis_when_present="The run-trace export shows retention enabled plus purpose capture, input classifications, output references, and human-review linkage for the scoped AI-assisted operation.",
            basis_when_missing="No typed AI rights-ready run-trace export is attached to this AI governance corridor.",
            basis_when_failed="The AI rights-ready run-trace export was present but did not satisfy the narrow retained-trace predicate.",
            predicate=_ai_rights_ready_run_trace_state,
            classification_rationale="A structured run trace can be checked mechanically when the AI surface emits a typed rights-ready trace artifact.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-715",
            title="The AI supplier and transfer map is current for the scoped AI-assisted operation and names subprocessors plus transfer mechanism coverage.",
            route="attestation",
            expected_claim_type="ai_supplier_transfer_attestation",
            control_refs=["oc.ai-13"],
            default_framework_mappings=[],
            basis_when_present="The AI supplier-transfer claim is a signed synthetic attestation covering current supplier inventory, declared subprocessor roles, and transfer mechanism coverage for the scoped operation.",
            basis_when_missing="No typed AI supplier-transfer attestation is attached to this AI governance corridor.",
            basis_when_failed="The AI supplier-transfer attestation was present but did not satisfy the current corridor predicate.",
            predicate=_ai_supplier_transfer_attestation,
            classification_rationale="Supplier and transfer governance remains documentary, but the corridor should still expose it explicitly rather than hiding it inside a generic vendor placeholder.",
        ),
        VerificationItemSpec(
            claim_id="EX-CLAIM-716",
            title="The privacy notice for the scoped AI-assisted surface is currently published, reachable, and linked to the active rights path.",
            route="decidable",
            expected_claim_type="privacy_notice_publication_state",
            control_refs=["oc.privacy-06"],
            default_framework_mappings=[],
            basis_when_present="The notice-publication export shows the scoped AI notice is published, reachable, lists categories and purposes, and links to the active rights path.",
            basis_when_missing="No typed privacy-notice publication export is attached to this AI governance corridor.",
            basis_when_failed="The privacy-notice publication export was present but did not satisfy the narrow publication-state predicate.",
            predicate=_privacy_notice_publication_state,
            classification_rationale="Notice publication state is machine-checkable when the scoped public surface exports a typed snapshot of publication and reachability facts.",
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
