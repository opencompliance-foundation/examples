from __future__ import annotations

import json
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .evidence import EvidenceRegistry
from .example_specs import FIXTURE_SPECS
from .paths import find_repo_root
from .lean_tooling import ensure_lean_package_ready
from .models import FixtureSpec


def _bool_literal(value: bool) -> str:
    return "true" if value else "false"


def _string_literal(value: str) -> str:
    return "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\""


def _string_list_literal(values: list[str]) -> str:
    return "[" + ", ".join(_string_literal(value) for value in values) + "]"


def _select_fixture_spec(fixture_root: Path) -> FixtureSpec:
    return FIXTURE_SPECS[fixture_root.name]


@dataclass(frozen=True)
class LeanObligation:
    claim_id: str
    control_id: str
    module: str
    predicate: str
    evidence_claim_type: str
    theorem_name: str
    block_text: str


def _identity_block(name: str, payload: dict) -> str:
    return f"""
def {name} : OpenCompliance.Controls.IdentityEvidence := {{
  mfaRequired := {_bool_literal(payload['mfaRequired'])}
  conditionalAccessEnabled := {_bool_literal(payload['conditionalAccessEnabled'])}
}}

theorem {name}_proved :
    OpenCompliance.Controls.AdministrativeMfaSatisfied {name} := by
  exact OpenCompliance.Controls.administrativeMfaSatisfied_of_flags {name} rfl rfl
"""


def _unique_infrastructure_auth_block(name: str, payload: dict) -> str:
    return f"""
def {name} : OpenCompliance.Controls.InfrastructureAuthUniquenessEvidence := {{
  namedAccountsRequired := {_bool_literal(payload['namedAccountsRequired'])}
  sharedAccountsPresent := {_bool_literal(payload['sharedAccountsPresent'])}
}}

theorem {name}_proved :
    OpenCompliance.Controls.UniqueInfrastructureAuthenticationSatisfied {name} := by
  exact OpenCompliance.Controls.uniqueInfrastructureAuthenticationSatisfied_of_flags {name} rfl rfl
"""


def _password_policy_block(name: str, payload: dict) -> str:
    return f"""
def {name} : OpenCompliance.Controls.PasswordPolicyEvidence := {{
  minimumLengthAtLeast12 := {_bool_literal(payload['minimumLengthAtLeast12'])}
  noMaximumLengthRestriction := {_bool_literal(payload['noMaximumLengthRestriction'])}
  commonPasswordBlockingEnabled := {_bool_literal(payload['commonPasswordBlockingEnabled'])}
}}

theorem {name}_proved :
    OpenCompliance.Controls.ScopedPasswordPolicySatisfied {name} := by
  exact OpenCompliance.Controls.scopedPasswordPolicySatisfied_of_flags {name} rfl rfl rfl
"""


def _access_review_export_block(name: str, payload: dict) -> str:
    review_population_declared = bool(payload["reviewPopulation"])
    return f"""
def {name} : OpenCompliance.Controls.AccessReviewExportEvidence := {{
  reviewCompleted := {_bool_literal(payload['reviewCompleted'])}
  reviewWindowDays := {payload['reviewWindowDays']}
  reviewPopulationDeclared := {_bool_literal(review_population_declared)}
}}

theorem {name}_proved :
    OpenCompliance.Controls.TypedPeriodicAccessReviewExportPresent {name} := by
  exact OpenCompliance.Controls.typedPeriodicAccessReviewExportPresent_of_components {name} rfl (by decide) rfl
"""


def _web_application_firewall_block(name: str, payload: dict) -> str:
    return f"""
def {name} : OpenCompliance.Controls.WebApplicationFirewallEvidence := {{
  wafAttachedToPublicIngress := {_bool_literal(payload['wafAttachedToPublicIngress'])}
  blockingModeEnabled := {_bool_literal(payload['blockingModeEnabled'])}
  managedRuleSetActive := {_bool_literal(payload['managedRuleSetActive'])}
}}

theorem {name}_proved :
    OpenCompliance.Controls.WebApplicationFirewallSatisfied {name} := by
  exact OpenCompliance.Controls.webApplicationFirewallSatisfied_of_flags {name} rfl rfl rfl
"""


def _repo_branch_protection_block(name: str, payload: dict) -> str:
    return f"""
def {name} : OpenCompliance.Controls.RepoBranchProtectionEvidence := {{
  defaultBranchProtected := {_bool_literal(payload['defaultBranchProtected'])}
  requiredApprovals := {payload['requiredApprovals']}
  statusChecksRequired := {_bool_literal(payload['statusChecksRequired'])}
  forcePushesBlocked := {_bool_literal(payload['forcePushesBlocked'])}
  adminBypassRestricted := {_bool_literal(payload['adminBypassRestricted'])}
}}

theorem {name}_proved :
    OpenCompliance.Controls.DefaultBranchProtectionsEnforced {name} := by
  exact OpenCompliance.Controls.defaultBranchProtectionsEnforced_of_components {name} rfl (by decide) rfl rfl rfl
"""


def _ci_workflow_policy_block(name: str, payload: dict) -> str:
    return f"""
def {name} : OpenCompliance.Controls.CiWorkflowPolicyEvidence := {{
  workflowReviewRequired := {_bool_literal(payload['workflowReviewRequired'])}
  trustedPublishingOnly := {_bool_literal(payload['trustedPublishingOnly'])}
  protectedRefsOnly := {_bool_literal(payload['protectedRefsOnly'])}
  environmentApprovalsRequired := {_bool_literal(payload['environmentApprovalsRequired'])}
}}

theorem {name}_proved :
    OpenCompliance.Controls.CiWorkflowPolicyConstrained {name} := by
  exact OpenCompliance.Controls.ciWorkflowPolicyConstrained_of_flags {name} rfl rfl rfl rfl
"""


def _environment_segmentation_block(name: str, payload: dict) -> str:
    return f"""
def {name} : OpenCompliance.Controls.EnvironmentSegmentationEvidence := {{
  customerBoundaryEnforced := {_bool_literal(payload['customerBoundaryEnforced'])}
  productionSeparatedFromNonProduction := {_bool_literal(payload['productionSeparatedFromNonProduction'])}
  undeclaredCrossEnvironmentPathsPresent := {_bool_literal(payload['undeclaredCrossEnvironmentPathsPresent'])}
}}

theorem {name}_proved :
    OpenCompliance.Controls.EnvironmentSegmentationSatisfied {name} := by
  exact OpenCompliance.Controls.environmentSegmentationSatisfied_of_flags {name} rfl rfl rfl
"""


def _logging_block(name: str, payload: dict) -> str:
    return f"""
def {name} : OpenCompliance.Controls.AuditLoggingEvidence := {{
  auditLoggingEnabled := {_bool_literal(payload['auditLoggingEnabled'])}
  retentionDays := {payload['retentionDays']}
}}

theorem {name}_proved :
    OpenCompliance.Controls.NarrowAuditLoggingCorridor {name} := by
  refine OpenCompliance.Controls.narrowAuditLoggingCorridor_of_components {name} ?_ ?_
  · rfl
  · unfold OpenCompliance.Controls.RetentionWindowDeclared {name}
    decide
"""


def _central_monitoring_block(name: str, payload: dict) -> str:
    return f"""
def {name} : OpenCompliance.Controls.CentralMonitoringEvidence := {{
  centralSinkConfigured := {_bool_literal(payload['centralSinkConfigured'])}
  scopedAssetsForwarded := {_bool_literal(payload['scopedAssetsForwarded'])}
  alertRulesEnabled := {_bool_literal(payload['alertRulesEnabled'])}
}}

theorem {name}_proved :
    OpenCompliance.Controls.CentralizedMonitoringSatisfied {name} := by
  exact OpenCompliance.Controls.centralizedMonitoringSatisfied_of_flags {name} rfl rfl rfl
"""


def _secure_configuration_block(name: str, payload: dict) -> str:
    return f"""
def {name} : OpenCompliance.Controls.SecureConfigurationEvidence := {{
  baselineApplied := {_bool_literal(payload['baselineApplied'])}
  insecureDefaultsPresent := {_bool_literal(payload['insecureDefaultsPresent'])}
  snapshotAgeDays := {payload['snapshotAgeDays']}
}}

theorem {name}_proved :
    OpenCompliance.Controls.SecureConfigurationBaselineSatisfied {name} := by
  exact OpenCompliance.Controls.secureConfigurationBaselineSatisfied_of_components {name} rfl rfl (by decide)
"""


def _security_update_block(name: str, payload: dict) -> str:
    return f"""
def {name} : OpenCompliance.Controls.SecurityUpdateEvidence := {{
  supportedVersionsOnly := {_bool_literal(payload['supportedVersionsOnly'])}
  criticalOverdueCount := {payload['criticalOverdueCount']}
  patchWindowDays := {payload['patchWindowDays']}
}}

theorem {name}_proved :
    OpenCompliance.Controls.SupportedSecurityUpdatesCurrent {name} := by
  exact OpenCompliance.Controls.supportedSecurityUpdatesCurrent_of_components {name} rfl rfl (by decide)
"""


def _malware_protection_block(name: str, payload: dict) -> str:
    return f"""
def {name} : OpenCompliance.Controls.MalwareProtectionEvidence := {{
  protectionEnabled := {_bool_literal(payload['protectionEnabled'])}
  signaturesCurrent := {_bool_literal(payload['signaturesCurrent'])}
  tamperProtectionEnabled := {_bool_literal(payload['tamperProtectionEnabled'])}
}}

theorem {name}_proved :
    OpenCompliance.Controls.MalwareProtectionBaselineSatisfied {name} := by
  exact OpenCompliance.Controls.malwareProtectionBaselineSatisfied_of_flags {name} rfl rfl rfl
"""


def _network_block(name: str, payload: dict) -> str:
    tls_ok = payload["minTlsVersion"] in {"1.2", "1.3"}
    return f"""
def {name} : OpenCompliance.Controls.TlsIngressEvidence := {{
  httpsOnly := {_bool_literal(payload['httpsOnly'])}
  minTlsVersion12OrHigher := {_bool_literal(tls_ok)}
  managedCertificatesActive := {_bool_literal(payload['managedCertificatesActive'])}
  plaintextDisabled := {_bool_literal(payload['plaintextDisabled'])}
}}

theorem {name}_proved :
    OpenCompliance.Controls.TlsIngressSatisfied {name} := by
  exact OpenCompliance.Controls.tlsIngressSatisfied_of_flags {name} rfl rfl rfl
"""


def _plaintext_transport_block(name: str, payload: dict) -> str:
    tls_ok = payload["minTlsVersion"] in {"1.2", "1.3"}
    return f"""
def {name} : OpenCompliance.Controls.TlsIngressEvidence := {{
  httpsOnly := {_bool_literal(payload['httpsOnly'])}
  minTlsVersion12OrHigher := {_bool_literal(tls_ok)}
  managedCertificatesActive := {_bool_literal(payload['managedCertificatesActive'])}
  plaintextDisabled := {_bool_literal(payload['plaintextDisabled'])}
}}

theorem {name}_proved :
    OpenCompliance.Controls.PlaintextTransportDisabled {name} := by
  exact OpenCompliance.Controls.plaintextTransportDisabled_of_flags {name} rfl rfl
"""


def _encryption_at_rest_block(name: str, payload: dict) -> str:
    return f"""
def {name} : OpenCompliance.Controls.EncryptionAtRestEvidence := {{
  encryptionEnabled := {_bool_literal(payload['encryptionEnabled'])}
  customerDataStoresCovered := {_bool_literal(payload['customerDataStoresCovered'])}
  unencryptedStoresPresent := {_bool_literal(payload['unencryptedStoresPresent'])}
}}

theorem {name}_proved :
    OpenCompliance.Controls.EncryptionAtRestSatisfied {name} := by
  exact OpenCompliance.Controls.encryptionAtRestSatisfied_of_flags {name} rfl rfl rfl
"""


def _network_boundary_evidence_block(name: str, payload: dict) -> str:
    ports_declared = bool(payload["declaredIngressPorts"])
    approved_ranges_declared = bool(payload["approvedAdminSourceRanges"])
    return f"""
def {name} : OpenCompliance.Controls.NetworkBoundaryEvidence := {{
  defaultDenyInbound := {_bool_literal(payload['defaultDenyInbound'])}
  declaredIngressPortsPresent := {_bool_literal(ports_declared)}
  undeclaredIngressPresent := {_bool_literal(payload['undeclaredIngressPresent'])}
  boundaryAttachedToIngressPath := {_bool_literal(payload['boundaryAttachedToIngressPath'])}
  adminIngressRestricted := {_bool_literal(payload['adminIngressRestricted'])}
  approvedAdminSourceRangesDeclared := {_bool_literal(approved_ranges_declared)}
  unapprovedAdminIngressPresent := {_bool_literal(payload['unapprovedAdminIngressPresent'])}
}}
"""


def _default_deny_boundary_block(name: str, payload: dict) -> str:
    return _network_boundary_evidence_block(name, payload) + f"""
theorem {name}_proved :
    OpenCompliance.Controls.DefaultDenyNetworkBoundarySatisfied {name} := by
  exact OpenCompliance.Controls.defaultDenyNetworkBoundarySatisfied_of_flags {name} rfl rfl rfl
"""


def _managed_ingress_boundary_block(name: str, payload: dict) -> str:
    return _network_boundary_evidence_block(name, payload) + f"""
theorem {name}_proved :
    OpenCompliance.Controls.ManagedIngressBoundaryAttached {name} := by
  exact OpenCompliance.Controls.managedIngressBoundaryAttached_of_flags {name} rfl rfl rfl rfl
"""


def _admin_ingress_restricted_block(name: str, payload: dict) -> str:
    return _network_boundary_evidence_block(name, payload) + f"""
theorem {name}_proved :
    OpenCompliance.Controls.AdministrativeIngressRestricted {name} := by
  exact OpenCompliance.Controls.administrativeIngressRestricted_of_flags {name} rfl rfl rfl rfl rfl rfl
"""


def _keys_block(name: str, payload: dict) -> str:
    return f"""
def {name} : OpenCompliance.Controls.ServiceAccountKeyEvidence := {{
  userManagedKeysPresent := {_bool_literal(payload['userManagedKeysPresent'])}
  maxUserManagedKeyAgeDays := {payload['maxUserManagedKeyAgeDays']}
}}

theorem {name}_proved :
    OpenCompliance.Controls.NarrowServiceAccountKeyCorridor {name} := by
  exact OpenCompliance.Controls.narrowServiceAccountKeyCorridor_of_flags {name} rfl rfl
"""


def _location_block(name: str, payload: dict) -> str:
    approved = _string_list_literal(payload["approvedRegions"])
    observed = _string_list_literal(payload["observedRegions"])
    undeclared = _bool_literal(payload["undeclaredRegionsPresent"])
    return f"""
def {name} : OpenCompliance.Controls.ApprovedRegionEvidence := {{
  approvedRegions := {approved}
  observedRegions := {observed}
  undeclaredRegionsPresent := {undeclared}
}}

theorem {name}_proved :
    OpenCompliance.Controls.ApprovedRegionBoundarySatisfied {name} := by
  refine OpenCompliance.Controls.approvedRegionBoundarySatisfied_of_components {name} ?_ ?_ ?_ ?_
  · simp [OpenCompliance.Controls.ApprovedRegionsDeclared, {name}]
  · simp [OpenCompliance.Controls.ObservedRegionsDeclared, {name}]
  · unfold OpenCompliance.Controls.ObservedRegionsWithinApproved {name}
    native_decide
  · rfl
"""


def _backup_block(name: str, payload: dict) -> str:
    return f"""
def {name} : OpenCompliance.Controls.BackupSnapshotEvidence := {{
  snapshotsEnabled := {_bool_literal(payload['snapshotsEnabled'])}
  snapshotFrequencyHours := {payload['snapshotFrequencyHours']}
  immutableWindowDays := {payload['immutableWindowDays']}
}}

theorem {name}_proved :
    OpenCompliance.Controls.BackupSnapshotScheduleSatisfied {name} := by
  refine OpenCompliance.Controls.backupSnapshotScheduleSatisfied_of_components {name} ?_ ?_ ?_
  · rfl
  · unfold OpenCompliance.Controls.SnapshotFrequencyDeclared {name}
    decide
  · unfold OpenCompliance.Controls.ImmutableWindowDeclared {name}
    decide
"""


def _ai_content_labeling_block(name: str, payload: dict) -> str:
    return f"""
def {name} : OpenCompliance.Controls.AiContentLabelingEvidence := {{
  labelingEnabled := {_bool_literal(payload['labelingEnabled'])}
  metadataMarkerEnabled := {_bool_literal(payload['metadataMarkerEnabled'])}
  enforcementChecksPassing := {_bool_literal(payload['enforcementChecksPassing'])}
}}

theorem {name}_proved :
    OpenCompliance.Controls.AiGeneratedContentDisclosureConfigured {name} := by
  exact OpenCompliance.Controls.aiGeneratedContentDisclosureConfigured_of_flags {name} rfl rfl rfl
"""


BLOCK_BUILDERS = {
    "oc.id-01": _identity_block,
    "oc.id-04": _unique_infrastructure_auth_block,
    "oc.id-05": _password_policy_block,
    "oc.id-02": _access_review_export_block,
    "oc.web-01": _web_application_firewall_block,
    "oc.repo-01": _repo_branch_protection_block,
    "oc.ci-01": _ci_workflow_policy_block,
    "oc.seg-01": _environment_segmentation_block,
    "oc.log-01": _logging_block,
    "oc.mon-01": _central_monitoring_block,
    "oc.cfg-01": _secure_configuration_block,
    "oc.patch-01": _security_update_block,
    "oc.malware-01": _malware_protection_block,
    "oc.net-01": _network_block,
    "oc.net-04": _plaintext_transport_block,
    "oc.crypt-01": _encryption_at_rest_block,
    "oc.key-01": _keys_block,
    "oc.loc-01": _location_block,
    "oc.backup-01": _backup_block,
    "oc.boundary-01": _default_deny_boundary_block,
    "oc.net-02": _managed_ingress_boundary_block,
    "oc.net-03": _admin_ingress_restricted_block,
    "oc.ai-05": _ai_content_labeling_block,
}


def _typed_boundary_layer(runtime_context: dict[str, object] | None = None) -> dict[str, object]:
    runtime_context = runtime_context or {}
    runtime_consumed_claims = runtime_context.get("runtimeConsumedClaims", [])
    return {
        "source": "LegalLean",
        "dependency": {
            "package": "legal-lean",
            "primaryImports": [
                "LegalLean.Core",
                "LegalLean.Defeasible",
                "LegalLean.Solver",
            ],
        },
        "typedModules": [
            {
                "module": "OpenCompliance.Controls.Typed.TypedIdentity",
                "covers": [
                    "FormalisationBoundary.formal",
                    "FormalisationBoundary.boundary",
                    "RequiresHumanDetermination",
                ],
            },
            {
                "module": "OpenCompliance.Controls.Typed.TypedLogging",
                "covers": [
                    "FormalisationBoundary.formal",
                    "FormalisationBoundary.boundary",
                    "narrow_audit_logging_runtime",
                ],
            },
            {
                "module": "OpenCompliance.Controls.Typed.RiskAcceptance",
                "covers": [
                    "Defeats",
                    "risk_acceptance_override",
                ],
            },
            {
                "module": "OpenCompliance.Controls.Typed.DiscretionaryTerms",
                "covers": [
                    "Vague",
                    "judgment_boundary_inventory",
                ],
            },
            {
                "module": "OpenCompliance.Controls.Typed.ComplianceSolver",
                "covers": [
                    "LegalLean.Solver",
                    "minimal_claim_corpus",
                    "runtime_claim_decisions",
                ],
            },
            {
                "module": "OpenCompliance.Controls.Typed.PublicRuntime",
                "covers": [
                    "formalDecision",
                    "documentaryDecision",
                    "judgmentDecision",
                    "public_corridor_runtime_claim_decisions",
                ],
            },
        ],
        "runtimeConsumedClaims": runtime_consumed_claims,
        "runtimeStatus": {
            "typedControlResultsLive": True,
            "riskAcceptanceDefeasibilityLive": True,
            "discretionaryTermTypingLive": True,
            "fullMinimalSolverAgreement": bool(runtime_context.get("fullMinimalSolverAgreement", False)),
            "pythonVerdictLayerReplaced": bool(runtime_context.get("pythonVerdictLayerReplaced", False)),
        },
    }


def _load_control_boundaries(fixture_root: Path) -> dict[str, dict]:
    repo_root = find_repo_root(fixture_root)
    boundaries = json.loads((repo_root / "open-specs" / "control-boundaries.json").read_text())
    return {control["controlId"]: control for control in boundaries["controls"]}


def _supported_obligations(
    fixture_root: Path,
    registry: EvidenceRegistry,
    proof_bundle: dict,
) -> tuple[list[LeanObligation], list[dict[str, object]]]:
    boundaries_by_id = _load_control_boundaries(fixture_root)
    obligations: list[LeanObligation] = []
    omitted_proved_claims: list[dict[str, object]] = []

    for claim in proof_bundle["claims"]:
        if claim["result"] != "proved":
            continue
        if not claim["evidenceRefs"]:
            omitted_proved_claims.append(
                {
                    "claimId": claim["claimId"],
                    "title": claim["title"],
                    "controlRefs": claim["controlRefs"],
                    "reason": "no_evidence_ref",
                }
            )
            continue

        selected_boundary = None
        for control_ref in claim["controlRefs"]:
            boundary = boundaries_by_id.get(control_ref)
            if boundary and boundary.get("lean") is not None:
                selected_boundary = boundary
                break

        if selected_boundary is None:
            omitted_proved_claims.append(
                {
                    "claimId": claim["claimId"],
                    "title": claim["title"],
                    "controlRefs": claim["controlRefs"],
                    "reason": "no_public_lean_predicate",
                }
            )
            continue

        builder = BLOCK_BUILDERS.get(selected_boundary["controlId"])
        if builder is None:
            omitted_proved_claims.append(
                {
                    "claimId": claim["claimId"],
                    "title": claim["title"],
                    "controlRefs": claim["controlRefs"],
                    "reason": "no_registered_batch_builder",
                }
            )
            continue

        evidence = registry.get(claim["evidenceRefs"][0])
        expected_claim_type = selected_boundary.get("evidenceClaimType")
        if expected_claim_type and evidence.claim_type != expected_claim_type:
            raise ValueError(
                f"Lean boundary mismatch for {claim['claimId']}: expected {expected_claim_type}, got {evidence.claim_type}"
            )

        lean = selected_boundary["lean"]
        name = f"claim_{claim['claimId'].replace('-', '_')}"
        obligations.append(
            LeanObligation(
                claim_id=claim["claimId"],
                control_id=selected_boundary["controlId"],
                module=lean["module"],
                predicate=lean["predicate"],
                evidence_claim_type=evidence.claim_type,
                theorem_name=f"{name}_proved",
                block_text=builder(name, evidence.payload),
            )
        )

    return obligations, omitted_proved_claims


def _batch_text(
    fixture_root: Path,
    registry: EvidenceRegistry,
    proof_bundle: dict,
) -> tuple[str, list[LeanObligation], list[dict[str, object]]]:
    obligations, omitted_proved_claims = _supported_obligations(fixture_root, registry, proof_bundle)
    blocks = [obligation.block_text for obligation in obligations]
    imports = sorted({obligation.module for obligation in obligations})

    header = "\n".join(f"import {module}" for module in imports)
    if header:
        header += "\n\n"
    header += "namespace OpenCompliance.Generated\n"
    footer = "\nend OpenCompliance.Generated\n"
    return header + "\n".join(blocks) + footer, obligations, omitted_proved_claims


def run_lean_batch(
    fixture_root: Path,
    proof_bundle: dict,
    runtime_context: dict[str, object] | None = None,
) -> dict[str, object]:
    registry = EvidenceRegistry.from_path(fixture_root / "evidence-claims.json")
    batch_text, obligations, omitted_proved_claims = _batch_text(fixture_root, registry, proof_bundle)
    lean_root = find_repo_root(fixture_root) / "lean4-controls"
    ensure_lean_package_ready(str(lean_root))

    with tempfile.TemporaryDirectory(dir=lean_root) as temp_dir_raw:
        temp_dir = Path(temp_dir_raw)
        batch_path = temp_dir / f"{fixture_root.name}_batch.lean"
        batch_path.write_text(batch_text)
        result = subprocess.run(
            ["lake", "env", "lean", str(batch_path)],
            cwd=lean_root,
            capture_output=True,
            text=True,
            check=False,
        )

    if result.returncode != 0:
        raise ValueError(
            "Lean proof batch failed for "
            f"{fixture_root.name}:\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
        )

    spec = _select_fixture_spec(fixture_root)
    return {
        "batchId": f"{spec.bundle_id}-lean-batch",
        "fixture": spec.fixture_name,
        "status": "verified",
        "theoremCount": len(obligations),
        "verifiedTheorems": [obligation.theorem_name for obligation in obligations],
        "importedModules": sorted({obligation.module for obligation in obligations}),
        "verifiedClaims": [
            {
                "claimId": obligation.claim_id,
                "controlId": obligation.control_id,
                "module": obligation.module,
                "predicate": obligation.predicate,
                "evidenceClaimType": obligation.evidence_claim_type,
                "theorem": obligation.theorem_name,
            }
            for obligation in obligations
        ],
        "typedBoundaryLayer": _typed_boundary_layer(runtime_context),
        "boundaryInventory": {
            "provedClaimCount": sum(1 for claim in proof_bundle["claims"] if claim["result"] == "proved"),
            "leanBackedClaimCount": len(obligations),
            "omittedProvedClaims": omitted_proved_claims,
        },
        "command": ["lake", "env", "lean", "<generated-batch>"],
    }
