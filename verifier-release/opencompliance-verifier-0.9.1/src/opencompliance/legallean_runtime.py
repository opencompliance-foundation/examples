from __future__ import annotations

import json
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .evidence import EvidenceRegistry
from .freshness import claim_is_stale
from .lean_tooling import ensure_lean_package_ready
from .models import FixtureSpec, VerificationItemSpec
from .paths import find_repo_root


MINIMAL_SOLVER_FIXTURES = {"minimal", "failed", "stale"}
SUPPORTED_FIXTURES = {
    "minimal",
    "failed",
    "stale",
    "medium",
    "issued",
    "cyber-baseline",
    "ai-governance",
}


@dataclass(frozen=True)
class GenericRuntimeDecision:
    claim_id: str
    slot: str
    evidence_refs: list[str]
    definitions: str
    decision_name: str
    imports: tuple[str, ...]


def supports_legallean_runtime(fixture_root: Path, spec: FixtureSpec) -> bool:
    return fixture_root.name == spec.fixture_name and spec.fixture_name in SUPPORTED_FIXTURES


def _bool_literal(value: bool) -> str:
    return "true" if value else "false"


def _string_literal(value: str) -> str:
    return "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\""


def _string_list_literal(values: list[str]) -> str:
    return "[" + ", ".join(_string_literal(value) for value in values) + "]"


def _first_claim(registry: EvidenceRegistry, claim_type: str):
    claims = registry.by_type(claim_type)
    return claims[0] if claims else None


def _identity_literal(claim) -> str:
    if claim is None:
        return "none"
    payload = claim.payload
    return (
        "some { "
        f"mfaRequired := {_bool_literal(payload['mfaRequired'])}, "
        f"conditionalAccessEnabled := {_bool_literal(payload['conditionalAccessEnabled'])} "
        "}"
    )


def _logging_literal(claim) -> str:
    if claim is None:
        return "none"
    payload = claim.payload
    return (
        "some { "
        f"auditLoggingEnabled := {_bool_literal(payload['auditLoggingEnabled'])}, "
        f"retentionDays := {payload['retentionDays']} "
        "}"
    )


def _minimal_runtime_script(
    identity_claim,
    logging_claim,
    training_claim,
    restore_claim,
    generated_at: str,
) -> str:
    identity_fresh = identity_claim is not None and not claim_is_stale(identity_claim, generated_at)
    logging_fresh = logging_claim is not None and not claim_is_stale(logging_claim, generated_at)
    training_fresh = training_claim is not None and not claim_is_stale(training_claim, generated_at)
    restore_fresh = restore_claim is not None and not claim_is_stale(restore_claim, generated_at)
    training_signed = training_claim is not None and training_claim.actor_type == "human"
    restore_completed = bool(restore_claim and restore_claim.payload["restoreTestCompleted"])

    return f"""import Lean
import OpenCompliance.Controls.Typed.ComplianceSolver

open Lean
open OpenCompliance.Controls.Typed

instance : ToJson RuntimeVerdict where
  toJson verdict := toJson (runtimeVerdictLabel verdict)

instance : ToJson MinimalClaimSlot where
  toJson slot := toJson (minimalClaimSlotLabel slot)

instance : ToJson RuntimeClaimDecision where
  toJson decision :=
    Json.mkObj
      [("slot", toJson decision.slot),
       ("verdict", toJson decision.verdict),
       ("reason", toJson decision.reason),
       ("solverBoundaryTag", toJson decision.solverBoundaryTag),
       ("typedBoundaryTag", toJson decision.typedBoundaryTag)]

def runtimeInputs : MinimalRuntimeInputs := {{
  identity := {_identity_literal(identity_claim)}
  identityFresh := {_bool_literal(identity_fresh)}
  logging := {_logging_literal(logging_claim)}
  loggingFresh := {_bool_literal(logging_fresh)}
  trainingAttestationExists := {_bool_literal(training_claim is not None)}
  trainingAttestationSigned := {_bool_literal(training_signed)}
  trainingFresh := {_bool_literal(training_fresh)}
  policyAdequacyRequiresHumanReview := true
  restoreEvidenceAttached := {_bool_literal(restore_claim is not None)}
  restoreTestCompleted := {_bool_literal(restore_completed)}
  restoreFresh := {_bool_literal(restore_fresh)}
  riskAcceptance := none
}}

#eval IO.println (Json.compress (toJson (minimalRuntimeDecisions runtimeInputs)))
"""


def _run_minimal_runtime_decisions(
    fixture_root: Path,
    registry: EvidenceRegistry,
    generated_at: str,
) -> dict[str, dict[str, Any]]:
    identity_claim = _first_claim(registry, "identity_mfa_enforcement")
    logging_claim = _first_claim(registry, "audit_logging_state")
    training_claim = _first_claim(registry, "training_attestation")
    restore_claim = _first_claim(registry, "restore_test_attestation")
    script_text = _minimal_runtime_script(identity_claim, logging_claim, training_claim, restore_claim, generated_at)
    lean_root = find_repo_root(fixture_root) / "lean4-controls"
    ensure_lean_package_ready(str(lean_root))

    with tempfile.TemporaryDirectory(dir=lean_root) as temp_dir_raw:
        temp_dir = Path(temp_dir_raw)
        script_path = temp_dir / f"{fixture_root.name}_runtime.lean"
        script_path.write_text(script_text)
        result = subprocess.run(
            ["lake", "env", "lean", str(script_path)],
            cwd=lean_root,
            capture_output=True,
            text=True,
            check=False,
            timeout=120,
        )

    if result.returncode != 0:
        raise ValueError(
            "LegalLean runtime bridge failed for "
            f"{fixture_root.name}:\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
        )

    payload = json.loads(result.stdout.strip())
    return {entry["slot"]: entry for entry in payload}


def _slot_for_minimal_item(item: VerificationItemSpec) -> str | None:
    control_refs = set(item.control_refs)
    if item.expected_claim_type == "identity_mfa_enforcement" and "oc.id-01" in control_refs:
        return "identity"
    if item.expected_claim_type == "audit_logging_state" and "oc.log-01" in control_refs:
        return "logging"
    if item.expected_claim_type == "training_attestation" and "oc.train-01" in control_refs:
        return "training"
    if item.route == "judgment":
        families = {(mapping.framework, mapping.family) for mapping in item.default_framework_mappings}
        if ("SOC 2", "overall_control_adequacy") in families or ("ISO 27001", "overall_control_adequacy") in families:
            return "policy"
    if item.expected_claim_type == "restore_test_attestation" and "oc.rec-01" in control_refs:
        return "restore"
    return None


def _evidence_refs_for_slot(slot: str, registry: EvidenceRegistry) -> list[str]:
    claim_type = {
        "identity": "identity_mfa_enforcement",
        "logging": "audit_logging_state",
        "training": "training_attestation",
        "restore": "restore_test_attestation",
    }.get(slot)
    if claim_type is None:
        return []
    claims = registry.by_type(claim_type)
    return [claims[0].claim_id] if claims else []


def _formal_identity_block(base_name: str, payload: dict) -> tuple[tuple[str, ...], str]:
    return (
        ("OpenCompliance.Controls.Identity",),
        f"""
def {base_name}_evidence : OpenCompliance.Controls.IdentityEvidence := {{
  mfaRequired := {_bool_literal(payload['mfaRequired'])}
  conditionalAccessEnabled := {_bool_literal(payload['conditionalAccessEnabled'])}
}}

def {base_name}_satisfied : Bool :=
  {base_name}_evidence.mfaRequired &&
  {base_name}_evidence.conditionalAccessEnabled
""",
    )


def _formal_access_review_block(base_name: str, payload: dict) -> tuple[tuple[str, ...], str]:
    review_population_declared = bool(payload["reviewPopulation"])
    return (
        ("OpenCompliance.Controls.Identity",),
        f"""
def {base_name}_evidence : OpenCompliance.Controls.AccessReviewExportEvidence := {{
  reviewCompleted := {_bool_literal(payload['reviewCompleted'])}
  reviewWindowDays := {payload['reviewWindowDays']}
  reviewPopulationDeclared := {_bool_literal(review_population_declared)}
}}

def {base_name}_satisfied : Bool :=
  {base_name}_evidence.reviewCompleted &&
  decide (0 < {base_name}_evidence.reviewWindowDays) &&
  {base_name}_evidence.reviewPopulationDeclared
""",
    )


def _formal_unique_auth_block(base_name: str, payload: dict) -> tuple[tuple[str, ...], str]:
    return (
        ("OpenCompliance.Controls.Identity",),
        f"""
def {base_name}_evidence : OpenCompliance.Controls.InfrastructureAuthUniquenessEvidence := {{
  namedAccountsRequired := {_bool_literal(payload['namedAccountsRequired'])}
  sharedAccountsPresent := {_bool_literal(payload['sharedAccountsPresent'])}
}}

def {base_name}_satisfied : Bool :=
  {base_name}_evidence.namedAccountsRequired &&
  ({base_name}_evidence.sharedAccountsPresent == false)
""",
    )


def _formal_password_policy_block(base_name: str, payload: dict) -> tuple[tuple[str, ...], str]:
    return (
        ("OpenCompliance.Controls.Identity",),
        f"""
def {base_name}_evidence : OpenCompliance.Controls.PasswordPolicyEvidence := {{
  minimumLengthAtLeast12 := {_bool_literal(payload['minimumLengthAtLeast12'])}
  noMaximumLengthRestriction := {_bool_literal(payload['noMaximumLengthRestriction'])}
  commonPasswordBlockingEnabled := {_bool_literal(payload['commonPasswordBlockingEnabled'])}
}}

def {base_name}_satisfied : Bool :=
  {base_name}_evidence.minimumLengthAtLeast12 &&
  {base_name}_evidence.noMaximumLengthRestriction &&
  {base_name}_evidence.commonPasswordBlockingEnabled
""",
    )


def _formal_web_application_firewall_block(base_name: str, payload: dict) -> tuple[tuple[str, ...], str]:
    return (
        ("OpenCompliance.Controls.Network",),
        f"""
def {base_name}_evidence : OpenCompliance.Controls.WebApplicationFirewallEvidence := {{
  wafAttachedToPublicIngress := {_bool_literal(payload['wafAttachedToPublicIngress'])}
  blockingModeEnabled := {_bool_literal(payload['blockingModeEnabled'])}
  managedRuleSetActive := {_bool_literal(payload['managedRuleSetActive'])}
}}

def {base_name}_satisfied : Bool :=
  {base_name}_evidence.wafAttachedToPublicIngress &&
  {base_name}_evidence.blockingModeEnabled &&
  {base_name}_evidence.managedRuleSetActive
""",
    )


def _formal_environment_segmentation_block(base_name: str, payload: dict) -> tuple[tuple[str, ...], str]:
    return (
        ("OpenCompliance.Controls.Network",),
        f"""
def {base_name}_evidence : OpenCompliance.Controls.EnvironmentSegmentationEvidence := {{
  customerBoundaryEnforced := {_bool_literal(payload['customerBoundaryEnforced'])}
  productionSeparatedFromNonProduction := {_bool_literal(payload['productionSeparatedFromNonProduction'])}
  undeclaredCrossEnvironmentPathsPresent := {_bool_literal(payload['undeclaredCrossEnvironmentPathsPresent'])}
}}

def {base_name}_satisfied : Bool :=
  {base_name}_evidence.customerBoundaryEnforced &&
  {base_name}_evidence.productionSeparatedFromNonProduction &&
  ({base_name}_evidence.undeclaredCrossEnvironmentPathsPresent == false)
""",
    )


def _formal_logging_block(base_name: str, payload: dict) -> tuple[tuple[str, ...], str]:
    return (
        ("OpenCompliance.Controls.Logging",),
        f"""
def {base_name}_evidence : OpenCompliance.Controls.AuditLoggingEvidence := {{
  auditLoggingEnabled := {_bool_literal(payload['auditLoggingEnabled'])}
  retentionDays := {payload['retentionDays']}
}}

def {base_name}_satisfied : Bool :=
  {base_name}_evidence.auditLoggingEnabled &&
  decide (0 < {base_name}_evidence.retentionDays)
""",
    )


def _formal_central_monitoring_block(base_name: str, payload: dict) -> tuple[tuple[str, ...], str]:
    return (
        ("OpenCompliance.Controls.Logging",),
        f"""
def {base_name}_evidence : OpenCompliance.Controls.CentralMonitoringEvidence := {{
  centralSinkConfigured := {_bool_literal(payload['centralSinkConfigured'])}
  scopedAssetsForwarded := {_bool_literal(payload['scopedAssetsForwarded'])}
  alertRulesEnabled := {_bool_literal(payload['alertRulesEnabled'])}
}}

def {base_name}_satisfied : Bool :=
  {base_name}_evidence.centralSinkConfigured &&
  {base_name}_evidence.scopedAssetsForwarded &&
  {base_name}_evidence.alertRulesEnabled
""",
    )


def _formal_tls_ingress_block(
    base_name: str,
    payload: dict,
    predicate: str,
) -> tuple[tuple[str, ...], str]:
    tls_ok = payload["minTlsVersion"] in {"1.2", "1.3"}
    if predicate == "TlsIngressSatisfied":
        satisfied_expr = (
            f"{base_name}_evidence.httpsOnly && "
            f"{base_name}_evidence.minTlsVersion12OrHigher && "
            f"{base_name}_evidence.managedCertificatesActive"
        )
    else:
        satisfied_expr = f"{base_name}_evidence.httpsOnly && {base_name}_evidence.plaintextDisabled"
    return (
        ("OpenCompliance.Controls.Network",),
        f"""
def {base_name}_evidence : OpenCompliance.Controls.TlsIngressEvidence := {{
  httpsOnly := {_bool_literal(payload['httpsOnly'])}
  minTlsVersion12OrHigher := {_bool_literal(tls_ok)}
  managedCertificatesActive := {_bool_literal(payload['managedCertificatesActive'])}
  plaintextDisabled := {_bool_literal(payload['plaintextDisabled'])}
}}

def {base_name}_satisfied : Bool :=
  {satisfied_expr}
""",
    )


def _formal_network_boundary_block(
    base_name: str,
    payload: dict,
    predicate: str,
) -> tuple[tuple[str, ...], str]:
    declared_ports_present = bool(payload["declaredIngressPorts"])
    approved_ranges_declared = bool(payload["approvedAdminSourceRanges"])
    if predicate == "DefaultDenyNetworkBoundarySatisfied":
        satisfied_expr = (
            f"{base_name}_evidence.defaultDenyInbound && "
            f"{base_name}_evidence.declaredIngressPortsPresent && "
            f"({base_name}_evidence.undeclaredIngressPresent == false)"
        )
    elif predicate == "ManagedIngressBoundaryAttached":
        satisfied_expr = (
            f"{base_name}_evidence.defaultDenyInbound && "
            f"{base_name}_evidence.declaredIngressPortsPresent && "
            f"({base_name}_evidence.undeclaredIngressPresent == false) && "
            f"{base_name}_evidence.boundaryAttachedToIngressPath"
        )
    else:
        satisfied_expr = (
            f"{base_name}_evidence.defaultDenyInbound && "
            f"{base_name}_evidence.declaredIngressPortsPresent && "
            f"({base_name}_evidence.undeclaredIngressPresent == false) && "
            f"{base_name}_evidence.adminIngressRestricted && "
            f"{base_name}_evidence.approvedAdminSourceRangesDeclared && "
            f"({base_name}_evidence.unapprovedAdminIngressPresent == false)"
        )
    return (
        ("OpenCompliance.Controls.Network",),
        f"""
def {base_name}_evidence : OpenCompliance.Controls.NetworkBoundaryEvidence := {{
  defaultDenyInbound := {_bool_literal(payload['defaultDenyInbound'])}
  declaredIngressPortsPresent := {_bool_literal(declared_ports_present)}
  undeclaredIngressPresent := {_bool_literal(payload['undeclaredIngressPresent'])}
  boundaryAttachedToIngressPath := {_bool_literal(payload['boundaryAttachedToIngressPath'])}
  adminIngressRestricted := {_bool_literal(payload['adminIngressRestricted'])}
  approvedAdminSourceRangesDeclared := {_bool_literal(approved_ranges_declared)}
  unapprovedAdminIngressPresent := {_bool_literal(payload['unapprovedAdminIngressPresent'])}
}}

def {base_name}_satisfied : Bool :=
  {satisfied_expr}
""",
    )


def _formal_encryption_at_rest_block(base_name: str, payload: dict) -> tuple[tuple[str, ...], str]:
    return (
        ("OpenCompliance.Controls.Cryptography",),
        f"""
def {base_name}_evidence : OpenCompliance.Controls.EncryptionAtRestEvidence := {{
  encryptionEnabled := {_bool_literal(payload['encryptionEnabled'])}
  customerDataStoresCovered := {_bool_literal(payload['customerDataStoresCovered'])}
  unencryptedStoresPresent := {_bool_literal(payload['unencryptedStoresPresent'])}
}}

def {base_name}_satisfied : Bool :=
  {base_name}_evidence.encryptionEnabled &&
  {base_name}_evidence.customerDataStoresCovered &&
  ({base_name}_evidence.unencryptedStoresPresent == false)
""",
    )


def _formal_key_hygiene_block(base_name: str, payload: dict) -> tuple[tuple[str, ...], str]:
    return (
        ("OpenCompliance.Controls.Keys",),
        f"""
def {base_name}_evidence : OpenCompliance.Controls.ServiceAccountKeyEvidence := {{
  userManagedKeysPresent := {_bool_literal(payload['userManagedKeysPresent'])}
  maxUserManagedKeyAgeDays := {payload['maxUserManagedKeyAgeDays']}
}}

def {base_name}_satisfied : Bool :=
  ({base_name}_evidence.userManagedKeysPresent == false) &&
  ({base_name}_evidence.maxUserManagedKeyAgeDays == 0)
""",
    )


def _formal_region_boundary_block(base_name: str, payload: dict) -> tuple[tuple[str, ...], str]:
    approved_regions = _string_list_literal(payload["approvedRegions"])
    observed_regions = _string_list_literal(payload["observedRegions"])
    return (
        ("OpenCompliance.Controls.Location",),
        f"""
def {base_name}_evidence : OpenCompliance.Controls.ApprovedRegionEvidence := {{
  approvedRegions := {approved_regions}
  observedRegions := {observed_regions}
  undeclaredRegionsPresent := {_bool_literal(payload['undeclaredRegionsPresent'])}
}}

def {base_name}_observed_within_approved : Bool :=
  {base_name}_evidence.observedRegions.all
    (fun region => decide (region ∈ {base_name}_evidence.approvedRegions))

def {base_name}_satisfied : Bool :=
  ({base_name}_evidence.approvedRegions.isEmpty == false) &&
  ({base_name}_evidence.observedRegions.isEmpty == false) &&
  {base_name}_observed_within_approved &&
  ({base_name}_evidence.undeclaredRegionsPresent == false)
""",
    )


def _formal_backup_block(base_name: str, payload: dict) -> tuple[tuple[str, ...], str]:
    return (
        ("OpenCompliance.Controls.Backup",),
        f"""
def {base_name}_evidence : OpenCompliance.Controls.BackupSnapshotEvidence := {{
  snapshotsEnabled := {_bool_literal(payload['snapshotsEnabled'])}
  snapshotFrequencyHours := {payload['snapshotFrequencyHours']}
  immutableWindowDays := {payload['immutableWindowDays']}
}}

def {base_name}_satisfied : Bool :=
  {base_name}_evidence.snapshotsEnabled &&
  decide (0 < {base_name}_evidence.snapshotFrequencyHours) &&
  decide (0 < {base_name}_evidence.immutableWindowDays)
""",
    )


def _formal_repo_branch_protection_block(base_name: str, payload: dict) -> tuple[tuple[str, ...], str]:
    return (
        ("OpenCompliance.Controls.Development",),
        f"""
def {base_name}_evidence : OpenCompliance.Controls.RepoBranchProtectionEvidence := {{
  defaultBranchProtected := {_bool_literal(payload['defaultBranchProtected'])}
  requiredApprovals := {payload['requiredApprovals']}
  statusChecksRequired := {_bool_literal(payload['statusChecksRequired'])}
  forcePushesBlocked := {_bool_literal(payload['forcePushesBlocked'])}
  adminBypassRestricted := {_bool_literal(payload['adminBypassRestricted'])}
}}

def {base_name}_satisfied : Bool :=
  {base_name}_evidence.defaultBranchProtected &&
  decide (0 < {base_name}_evidence.requiredApprovals) &&
  {base_name}_evidence.statusChecksRequired &&
  {base_name}_evidence.forcePushesBlocked &&
  {base_name}_evidence.adminBypassRestricted
""",
    )


def _formal_ci_workflow_policy_block(base_name: str, payload: dict) -> tuple[tuple[str, ...], str]:
    return (
        ("OpenCompliance.Controls.Development",),
        f"""
def {base_name}_evidence : OpenCompliance.Controls.CiWorkflowPolicyEvidence := {{
  workflowReviewRequired := {_bool_literal(payload['workflowReviewRequired'])}
  trustedPublishingOnly := {_bool_literal(payload['trustedPublishingOnly'])}
  protectedRefsOnly := {_bool_literal(payload['protectedRefsOnly'])}
  environmentApprovalsRequired := {_bool_literal(payload['environmentApprovalsRequired'])}
}}

def {base_name}_satisfied : Bool :=
  {base_name}_evidence.workflowReviewRequired &&
  {base_name}_evidence.trustedPublishingOnly &&
  {base_name}_evidence.protectedRefsOnly &&
  {base_name}_evidence.environmentApprovalsRequired
""",
    )


def _formal_secure_configuration_block(base_name: str, payload: dict) -> tuple[tuple[str, ...], str]:
    return (
        ("OpenCompliance.Controls.Configuration",),
        f"""
def {base_name}_evidence : OpenCompliance.Controls.SecureConfigurationEvidence := {{
  baselineApplied := {_bool_literal(payload['baselineApplied'])}
  insecureDefaultsPresent := {_bool_literal(payload['insecureDefaultsPresent'])}
  snapshotAgeDays := {payload['snapshotAgeDays']}
}}

def {base_name}_satisfied : Bool :=
  {base_name}_evidence.baselineApplied &&
  ({base_name}_evidence.insecureDefaultsPresent == false) &&
  decide ({base_name}_evidence.snapshotAgeDays <= 30)
""",
    )


def _formal_security_update_block(base_name: str, payload: dict) -> tuple[tuple[str, ...], str]:
    return (
        ("OpenCompliance.Controls.Patching",),
        f"""
def {base_name}_evidence : OpenCompliance.Controls.SecurityUpdateEvidence := {{
  supportedVersionsOnly := {_bool_literal(payload['supportedVersionsOnly'])}
  criticalOverdueCount := {payload['criticalOverdueCount']}
  patchWindowDays := {payload['patchWindowDays']}
}}

def {base_name}_satisfied : Bool :=
  {base_name}_evidence.supportedVersionsOnly &&
  ({base_name}_evidence.criticalOverdueCount == 0) &&
  decide ({base_name}_evidence.patchWindowDays <= 14)
""",
    )


def _formal_malware_protection_block(base_name: str, payload: dict) -> tuple[tuple[str, ...], str]:
    return (
        ("OpenCompliance.Controls.Endpoint",),
        f"""
def {base_name}_evidence : OpenCompliance.Controls.MalwareProtectionEvidence := {{
  protectionEnabled := {_bool_literal(payload['protectionEnabled'])}
  signaturesCurrent := {_bool_literal(payload['signaturesCurrent'])}
  tamperProtectionEnabled := {_bool_literal(payload['tamperProtectionEnabled'])}
}}

def {base_name}_satisfied : Bool :=
  {base_name}_evidence.protectionEnabled &&
  {base_name}_evidence.signaturesCurrent &&
  {base_name}_evidence.tamperProtectionEnabled
""",
    )


def _formal_ai_content_labeling_block(base_name: str, payload: dict) -> tuple[tuple[str, ...], str]:
    return (
        ("OpenCompliance.Controls.AI",),
        f"""
def {base_name}_evidence : OpenCompliance.Controls.AiContentLabelingEvidence := {{
  labelingEnabled := {_bool_literal(payload['labelingEnabled'])}
  metadataMarkerEnabled := {_bool_literal(payload['metadataMarkerEnabled'])}
  enforcementChecksPassing := {_bool_literal(payload['enforcementChecksPassing'])}
}}

def {base_name}_satisfied : Bool :=
  {base_name}_evidence.labelingEnabled &&
  {base_name}_evidence.metadataMarkerEnabled &&
  {base_name}_evidence.enforcementChecksPassing
""",
    )


FORMAL_BUILDERS = {
    "oc.id-01": _formal_identity_block,
    "oc.id-02": _formal_access_review_block,
    "oc.id-04": _formal_unique_auth_block,
    "oc.id-05": _formal_password_policy_block,
    "oc.web-01": _formal_web_application_firewall_block,
    "oc.seg-01": _formal_environment_segmentation_block,
    "oc.log-01": _formal_logging_block,
    "oc.mon-01": _formal_central_monitoring_block,
    "oc.net-01": lambda base_name, payload: _formal_tls_ingress_block(
        base_name, payload, "TlsIngressSatisfied"
    ),
    "oc.net-04": lambda base_name, payload: _formal_tls_ingress_block(
        base_name, payload, "PlaintextTransportDisabled"
    ),
    "oc.crypt-01": _formal_encryption_at_rest_block,
    "oc.key-01": _formal_key_hygiene_block,
    "oc.loc-01": _formal_region_boundary_block,
    "oc.backup-01": _formal_backup_block,
    "oc.repo-01": _formal_repo_branch_protection_block,
    "oc.ci-01": _formal_ci_workflow_policy_block,
    "oc.cfg-01": _formal_secure_configuration_block,
    "oc.patch-01": _formal_security_update_block,
    "oc.malware-01": _formal_malware_protection_block,
    "oc.boundary-01": lambda base_name, payload: _formal_network_boundary_block(
        base_name, payload, "DefaultDenyNetworkBoundarySatisfied"
    ),
    "oc.net-02": lambda base_name, payload: _formal_network_boundary_block(
        base_name, payload, "ManagedIngressBoundaryAttached"
    ),
    "oc.net-03": lambda base_name, payload: _formal_network_boundary_block(
        base_name, payload, "AdministrativeIngressRestricted"
    ),
    "oc.ai-05": _formal_ai_content_labeling_block,
}


def _documentary_training_block(base_name: str, claim) -> str:
    return f"""
def {base_name}_satisfied : Bool :=
  {_bool_literal(claim.payload['trainingComplete'])} &&
  {_bool_literal(claim.actor_type == 'human')}
"""


def _documentary_restore_block(base_name: str, claim) -> str:
    return f"""
def {base_name}_satisfied : Bool :=
  {_bool_literal(claim.payload['restoreTestCompleted'])} &&
  {_bool_literal(claim.actor_type == 'human')}
"""


def _documentary_vendor_register_block(base_name: str, claim) -> str:
    return f"""
def {base_name}_satisfied : Bool :=
  {_bool_literal(claim.payload['registerCurrent'])} &&
  {_bool_literal(claim.payload['dpaCoverageDeclared'])} &&
  {_bool_literal(claim.actor_type == 'human')}
"""


def _documentary_dsr_runbook_block(base_name: str, claim) -> str:
    owner_declared = bool(claim.payload["ownerRole"])
    return f"""
def {base_name}_satisfied : Bool :=
  {_bool_literal(claim.payload['runbookApproved'])} &&
  {_bool_literal(owner_declared)} &&
  {_bool_literal(claim.actor_type == 'human')}
"""


def _documentary_change_review_block(base_name: str, claim) -> str:
    return f"""
def {base_name}_satisfied : Bool :=
  {_bool_literal(claim.payload['changeReviewPolicyApproved'])} &&
  {_bool_literal(claim.payload['emergencyChangeProcessDeclared'])} &&
  {_bool_literal(claim.actor_type == 'human')}
"""


def _documentary_access_review_closure_block(base_name: str, claim) -> str:
    no_high_risk_findings_open = claim.payload["highRiskFindingsOpen"] == 0
    return f"""
def {base_name}_satisfied : Bool :=
  {_bool_literal(claim.payload['reviewCompleted'])} &&
  {_bool_literal(no_high_risk_findings_open)} &&
  {_bool_literal(claim.actor_type == 'human')}
"""


def _documentary_monitoring_review_block(base_name: str, claim) -> str:
    owner_declared = bool(claim.payload["monitoringOwnerRole"])
    return f"""
def {base_name}_satisfied : Bool :=
  {_bool_literal(claim.payload['alertReviewCadenceDeclared'])} &&
  {_bool_literal(owner_declared)} &&
  {_bool_literal(claim.payload['retentionOperationsCovered'])} &&
  {_bool_literal(claim.actor_type == 'human')}
"""


def _documentary_configuration_exception_block(base_name: str, claim) -> str:
    no_expired_exceptions = claim.payload["expiredExceptionsCount"] == 0
    return f"""
def {base_name}_satisfied : Bool :=
  {_bool_literal(claim.payload['exceptionRegisterCurrent'])} &&
  {_bool_literal(no_expired_exceptions)} &&
  {_bool_literal(claim.actor_type == 'human')}
"""


def _documentary_patch_exception_block(base_name: str, claim) -> str:
    no_expired_exceptions = claim.payload["expiredExceptionsCount"] == 0
    return f"""
def {base_name}_satisfied : Bool :=
  {_bool_literal(claim.payload['exceptionRegisterCurrent'])} &&
  {_bool_literal(claim.payload['compensatingControlsDeclared'])} &&
  {_bool_literal(no_expired_exceptions)} &&
  {_bool_literal(claim.actor_type == 'human')}
"""


def _documentary_incident_runbook_block(base_name: str, claim) -> str:
    owner_declared = bool(claim.payload["ownerRole"])
    return f"""
def {base_name}_satisfied : Bool :=
  {_bool_literal(claim.payload['runbookApproved'])} &&
  {_bool_literal(owner_declared)} &&
  {_bool_literal(claim.actor_type == 'human')}
"""


def _documentary_incident_contact_matrix_block(base_name: str, claim) -> str:
    return f"""
def {base_name}_satisfied : Bool :=
  {_bool_literal(claim.payload['contactsCurrent'])} &&
  {_bool_literal(claim.payload['escalationPathDocumented'])} &&
  {_bool_literal(claim.actor_type == 'human')}
"""


def _documentary_vendor_security_terms_block(base_name: str, claim) -> str:
    high_risk_vendors_covered = claim.payload["highRiskVendorsCovered"] > 0
    return f"""
def {base_name}_satisfied : Bool :=
  {_bool_literal(claim.payload['requiredSecurityTermsPresent'])} &&
  {_bool_literal(claim.payload['privacyTermsPresent'])} &&
  {_bool_literal(high_risk_vendors_covered)} &&
  {_bool_literal(claim.actor_type == 'human')}
"""


def _documentary_ai_context_block(base_name: str, claim) -> str:
    return f"""
def {base_name}_satisfied : Bool :=
  {_bool_literal(claim.payload['intendedUseDocumented'])} &&
  {_bool_literal(claim.payload['deploymentContextDocumented'])} &&
  {_bool_literal(claim.payload['ownerAssigned'])} &&
  {_bool_literal(claim.actor_type == 'human')}
"""


def _documentary_ai_risk_management_block(base_name: str, claim) -> str:
    return f"""
def {base_name}_satisfied : Bool :=
  {_bool_literal(claim.payload['riskProcessDocumented'])} &&
  {_bool_literal(claim.payload['riskTolerancesDeclared'])} &&
  {_bool_literal(claim.actor_type == 'human')}
"""


def _documentary_ai_human_oversight_block(base_name: str, claim) -> str:
    return f"""
def {base_name}_satisfied : Bool :=
  {_bool_literal(claim.payload['oversightRolesAssigned'])} &&
  {_bool_literal(claim.payload['escalationPathDocumented'])} &&
  {_bool_literal(claim.payload['overrideResponsibilityDeclared'])} &&
  {_bool_literal(claim.actor_type == 'human')}
"""


def _documentary_ai_monitoring_block(base_name: str, claim) -> str:
    return f"""
def {base_name}_satisfied : Bool :=
  {_bool_literal(claim.payload['monitoringOwnerAssigned'])} &&
  {_bool_literal(claim.payload['incidentEscalationPathDocumented'])} &&
  {_bool_literal(claim.actor_type == 'human')}
"""


DOCUMENTARY_BUILDERS = {
    "training_attestation": _documentary_training_block,
    "restore_test_attestation": _documentary_restore_block,
    "vendor_register_attestation": _documentary_vendor_register_block,
    "dsr_runbook_attestation": _documentary_dsr_runbook_block,
    "change_review_attestation": _documentary_change_review_block,
    "access_review_closure_attestation": _documentary_access_review_closure_block,
    "monitoring_review_attestation": _documentary_monitoring_review_block,
    "configuration_exception_attestation": _documentary_configuration_exception_block,
    "patch_exception_attestation": _documentary_patch_exception_block,
    "incident_response_runbook_attestation": _documentary_incident_runbook_block,
    "incident_contact_matrix_attestation": _documentary_incident_contact_matrix_block,
    "vendor_security_terms_attestation": _documentary_vendor_security_terms_block,
    "ai_context_attestation": _documentary_ai_context_block,
    "ai_risk_management_attestation": _documentary_ai_risk_management_block,
    "ai_human_oversight_attestation": _documentary_ai_human_oversight_block,
    "ai_monitoring_attestation": _documentary_ai_monitoring_block,
}


def _claim_base_name(claim_id: str) -> str:
    return "claim_" + claim_id.replace("-", "_").lower()


def _generic_runtime_decision(item: VerificationItemSpec, registry: EvidenceRegistry, generated_at: str) -> GenericRuntimeDecision:
    slot = item.claim_id
    base_name = _claim_base_name(item.claim_id)

    if item.route == "judgment":
        return GenericRuntimeDecision(
            claim_id=item.claim_id,
            slot=slot,
            evidence_refs=[],
            definitions=(
                f"""
def {base_name}_decision : OpenCompliance.Controls.Typed.PublicRuntimeClaimDecision :=
  OpenCompliance.Controls.Typed.judgmentDecision {_string_literal(item.claim_id)} {_string_literal(slot)}
"""
            ),
            decision_name=f"{base_name}_decision",
            imports=(),
        )

    claim = _first_claim(registry, item.expected_claim_type or "")
    evidence_refs = [claim.claim_id] if claim is not None else []
    evidence_present = claim is not None
    evidence_fresh = evidence_present and not claim_is_stale(claim, generated_at)

    if item.route == "decidable":
        control_id = item.control_refs[0]
        builder = FORMAL_BUILDERS.get(control_id)
        if builder is None:
            raise ValueError(f"Unsupported formal runtime control {control_id} for {item.claim_id}")
        formal_definitions = ""
        imports: tuple[str, ...] = ()
        satisfied_name = f"{base_name}_satisfied"
        if claim is not None and evidence_fresh:
            imports, formal_definitions = builder(base_name, claim.payload)
        return GenericRuntimeDecision(
            claim_id=item.claim_id,
            slot=slot,
            evidence_refs=evidence_refs,
            definitions=(
                formal_definitions
                + f"""
def {base_name}_decision : OpenCompliance.Controls.Typed.PublicRuntimeClaimDecision :=
  OpenCompliance.Controls.Typed.formalDecision
    {_string_literal(item.claim_id)}
    {_string_literal(slot)}
    {_bool_literal(evidence_present)}
    {_bool_literal(evidence_fresh)}
    {satisfied_name if claim is not None and evidence_fresh else 'false'}
"""
            ),
            decision_name=f"{base_name}_decision",
            imports=imports,
        )

    builder = DOCUMENTARY_BUILDERS.get(item.expected_claim_type or "")
    if builder is None:
        raise ValueError(f"Unsupported documentary runtime claim type {item.expected_claim_type} for {item.claim_id}")

    documentary_definitions = ""
    if claim is not None and evidence_fresh:
        documentary_definitions = builder(base_name, claim)

    return GenericRuntimeDecision(
        claim_id=item.claim_id,
        slot=slot,
        evidence_refs=evidence_refs,
        definitions=(
            documentary_definitions
            + f"""
def {base_name}_decision : OpenCompliance.Controls.Typed.PublicRuntimeClaimDecision :=
  OpenCompliance.Controls.Typed.documentaryDecision
    {_string_literal(item.claim_id)}
    {_string_literal(slot)}
    {_bool_literal(evidence_present)}
    {_bool_literal(evidence_fresh)}
    {f'{base_name}_satisfied' if claim is not None and evidence_fresh else 'false'}
"""
        ),
        decision_name=f"{base_name}_decision",
        imports=(),
    )


def _generic_runtime_script(decisions: list[GenericRuntimeDecision]) -> str:
    imports = {"Lean", "OpenCompliance.Controls.Typed.PublicRuntime"}
    for decision in decisions:
        imports.update(decision.imports)
    import_lines = "\n".join(f"import {module}" for module in sorted(imports))
    definition_lines = "\n".join(decision.definitions for decision in decisions)
    decision_names = ",\n  ".join(decision.decision_name for decision in decisions)
    return f"""{import_lines}

open Lean
open OpenCompliance.Controls.Typed

{definition_lines}

def runtimeDecisions : List PublicRuntimeClaimDecision := [
  {decision_names}
]

#eval IO.println (Json.compress (toJson runtimeDecisions))
"""


def _run_generic_runtime_decisions(
    fixture_root: Path,
    spec: FixtureSpec,
    registry: EvidenceRegistry,
) -> dict[str, dict[str, Any]]:
    decisions = [_generic_runtime_decision(item, registry, spec.generated_at) for item in spec.items]
    script_text = _generic_runtime_script(decisions)
    lean_root = find_repo_root(fixture_root) / "lean4-controls"
    ensure_lean_package_ready(str(lean_root))

    with tempfile.TemporaryDirectory(dir=lean_root) as temp_dir_raw:
        temp_dir = Path(temp_dir_raw)
        script_path = temp_dir / f"{fixture_root.name}_public_runtime.lean"
        script_path.write_text(script_text)
        result = subprocess.run(
            ["lake", "env", "lean", str(script_path)],
            cwd=lean_root,
            capture_output=True,
            text=True,
            check=False,
            timeout=120,
        )

    if result.returncode != 0:
        raise ValueError(
            "LegalLean public runtime bridge failed for "
            f"{fixture_root.name}:\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
        )

    payload = json.loads(result.stdout.strip())
    evidence_refs_by_claim = {decision.claim_id: decision.evidence_refs for decision in decisions}
    return {
        entry["claimId"]: {
            "slot": entry["slot"],
            "result": entry["verdict"],
            "evidenceRefs": evidence_refs_by_claim.get(entry["claimId"], []),
            "solverBoundaryTag": entry["solverBoundaryTag"],
            "typedBoundaryTag": entry["typedBoundaryTag"],
        }
        for entry in payload
    }


def runtime_results_for_fixture(
    fixture_root: Path,
    spec: FixtureSpec,
    registry: EvidenceRegistry,
) -> dict[str, dict[str, Any]]:
    if not supports_legallean_runtime(fixture_root, spec):
        return {}

    if spec.fixture_name in MINIMAL_SOLVER_FIXTURES:
        decisions_by_slot = _run_minimal_runtime_decisions(fixture_root, registry, spec.generated_at)
        results: dict[str, dict[str, Any]] = {}
        for item in spec.items:
            slot = _slot_for_minimal_item(item)
            if slot is None:
                continue
            decision = decisions_by_slot[slot]
            results[item.claim_id] = {
                "slot": slot,
                "result": decision["verdict"],
                "evidenceRefs": _evidence_refs_for_slot(slot, registry),
                "solverBoundaryTag": decision["solverBoundaryTag"],
                "typedBoundaryTag": decision["typedBoundaryTag"],
            }
        return results

    return _run_generic_runtime_decisions(fixture_root, spec, registry)
