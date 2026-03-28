import OpenCompliance.Controls.Backup
import OpenCompliance.Controls.Cryptography
import OpenCompliance.Controls.Development
import OpenCompliance.Controls.Identity
import OpenCompliance.Controls.Keys
import OpenCompliance.Controls.Location
import OpenCompliance.Controls.Logging
import OpenCompliance.Controls.Network

namespace OpenCompliance.Examples

def mediumBundleId : String :=
  "exampleco-medium-bundle-2026-03-24"

def mediumIdentityEvidence : OpenCompliance.Controls.IdentityEvidence := {
  mfaRequired := true
  conditionalAccessEnabled := true
}

def mediumAuditLoggingEvidence : OpenCompliance.Controls.AuditLoggingEvidence := {
  auditLoggingEnabled := true
  retentionDays := 180
}

def mediumCentralMonitoringEvidence : OpenCompliance.Controls.CentralMonitoringEvidence := {
  centralSinkConfigured := true
  scopedAssetsForwarded := true
  alertRulesEnabled := true
}

def mediumTlsIngressEvidence : OpenCompliance.Controls.TlsIngressEvidence := {
  httpsOnly := true
  minTlsVersion12OrHigher := true
  managedCertificatesActive := true
  plaintextDisabled := true
}

def mediumEncryptionAtRestEvidence : OpenCompliance.Controls.EncryptionAtRestEvidence := {
  encryptionEnabled := true
  customerDataStoresCovered := true
  unencryptedStoresPresent := false
}

def mediumInfrastructureAuthUniquenessEvidence : OpenCompliance.Controls.InfrastructureAuthUniquenessEvidence := {
  namedAccountsRequired := true
  sharedAccountsPresent := false
}

def mediumPasswordPolicyEvidence : OpenCompliance.Controls.PasswordPolicyEvidence := {
  minimumLengthAtLeast12 := true
  noMaximumLengthRestriction := true
  commonPasswordBlockingEnabled := true
}

def mediumAccessReviewExportEvidence : OpenCompliance.Controls.AccessReviewExportEvidence := {
  reviewCompleted := true
  reviewWindowDays := 90
  reviewPopulationDeclared := true
}

def mediumWebApplicationFirewallEvidence : OpenCompliance.Controls.WebApplicationFirewallEvidence := {
  wafAttachedToPublicIngress := true
  blockingModeEnabled := true
  managedRuleSetActive := true
}

def mediumRepoBranchProtectionEvidence : OpenCompliance.Controls.RepoBranchProtectionEvidence := {
  defaultBranchProtected := true
  requiredApprovals := 2
  statusChecksRequired := true
  forcePushesBlocked := true
  adminBypassRestricted := true
}

def mediumCiWorkflowPolicyEvidence : OpenCompliance.Controls.CiWorkflowPolicyEvidence := {
  workflowReviewRequired := true
  trustedPublishingOnly := true
  protectedRefsOnly := true
  environmentApprovalsRequired := true
}

def mediumEnvironmentSegmentationEvidence : OpenCompliance.Controls.EnvironmentSegmentationEvidence := {
  customerBoundaryEnforced := true
  productionSeparatedFromNonProduction := true
  undeclaredCrossEnvironmentPathsPresent := false
}

def mediumNetworkBoundaryEvidence : OpenCompliance.Controls.NetworkBoundaryEvidence := {
  defaultDenyInbound := true
  declaredIngressPortsPresent := true
  undeclaredIngressPresent := false
  boundaryAttachedToIngressPath := true
  adminIngressRestricted := true
  approvedAdminSourceRangesDeclared := true
  unapprovedAdminIngressPresent := false
}

def mediumRemoteAccessPostureEvidence : OpenCompliance.Controls.RemoteAccessPostureEvidence := {
  remotePathDeclared := true
  devicePostureBounded := true
  systemCount := 24
}

def mediumServiceAccountKeyEvidence : OpenCompliance.Controls.ServiceAccountKeyEvidence := {
  userManagedKeysPresent := false
  maxUserManagedKeyAgeDays := 0
}

def mediumApprovedRegionEvidence : OpenCompliance.Controls.ApprovedRegionEvidence := {
  approvedRegions := ["eu-west-1", "au-southeast-1"]
  observedRegions := ["eu-west-1", "au-southeast-1"]
  undeclaredRegionsPresent := false
}

def mediumBackupSnapshotEvidence : OpenCompliance.Controls.BackupSnapshotEvidence := {
  snapshotsEnabled := true
  snapshotFrequencyHours := 24
  immutableWindowDays := 30
}

theorem exClaim101_proved :
    OpenCompliance.Controls.AdministrativeMfaSatisfied mediumIdentityEvidence := by
  constructor <;> rfl

theorem exClaim102_proved :
    OpenCompliance.Controls.NarrowAuditLoggingCorridor mediumAuditLoggingEvidence := by
  refine And.intro ?_ ?_
  · rfl
  · unfold OpenCompliance.Controls.RetentionWindowDeclared mediumAuditLoggingEvidence
    decide

theorem exClaim132_proved :
    OpenCompliance.Controls.CentralizedMonitoringSatisfied mediumCentralMonitoringEvidence := by
  exact OpenCompliance.Controls.centralizedMonitoringSatisfied_of_flags
    mediumCentralMonitoringEvidence rfl rfl rfl

theorem exClaim103_proved :
    OpenCompliance.Controls.TlsIngressSatisfied mediumTlsIngressEvidence := by
  exact OpenCompliance.Controls.tlsIngressSatisfied_of_flags
    mediumTlsIngressEvidence rfl rfl rfl

theorem exClaim124_proved :
    OpenCompliance.Controls.ManagedIngressBoundaryAttached mediumNetworkBoundaryEvidence := by
  exact OpenCompliance.Controls.managedIngressBoundaryAttached_of_flags
    mediumNetworkBoundaryEvidence rfl rfl rfl rfl

theorem exClaim125_proved :
    OpenCompliance.Controls.AdministrativeIngressRestricted mediumNetworkBoundaryEvidence := by
  exact OpenCompliance.Controls.administrativeIngressRestricted_of_flags
    mediumNetworkBoundaryEvidence rfl rfl rfl rfl rfl rfl

theorem exClaim145_proved :
    OpenCompliance.Controls.RemoteAccessPostureDeclared mediumRemoteAccessPostureEvidence := by
  exact OpenCompliance.Controls.remoteAccessPostureDeclared_of_components
    mediumRemoteAccessPostureEvidence rfl rfl (by decide)

theorem exClaim126_proved :
    OpenCompliance.Controls.PlaintextTransportDisabled mediumTlsIngressEvidence := by
  exact OpenCompliance.Controls.plaintextTransportDisabled_of_flags
    mediumTlsIngressEvidence rfl rfl

theorem exClaim127_proved :
    OpenCompliance.Controls.EncryptionAtRestSatisfied mediumEncryptionAtRestEvidence := by
  exact OpenCompliance.Controls.encryptionAtRestSatisfied_of_flags
    mediumEncryptionAtRestEvidence rfl rfl rfl

theorem exClaim128_proved :
    OpenCompliance.Controls.UniqueInfrastructureAuthenticationSatisfied mediumInfrastructureAuthUniquenessEvidence := by
  exact OpenCompliance.Controls.uniqueInfrastructureAuthenticationSatisfied_of_flags
    mediumInfrastructureAuthUniquenessEvidence rfl rfl

theorem exClaim130_proved :
    OpenCompliance.Controls.ScopedPasswordPolicySatisfied mediumPasswordPolicyEvidence := by
  exact OpenCompliance.Controls.scopedPasswordPolicySatisfied_of_flags
    mediumPasswordPolicyEvidence rfl rfl rfl

theorem exClaim112_proved :
    OpenCompliance.Controls.TypedPeriodicAccessReviewExportPresent mediumAccessReviewExportEvidence := by
  exact OpenCompliance.Controls.typedPeriodicAccessReviewExportPresent_of_components
    mediumAccessReviewExportEvidence rfl (by decide) rfl

theorem exClaim131_proved :
    OpenCompliance.Controls.WebApplicationFirewallSatisfied mediumWebApplicationFirewallEvidence := by
  exact OpenCompliance.Controls.webApplicationFirewallSatisfied_of_flags
    mediumWebApplicationFirewallEvidence rfl rfl rfl

theorem exClaim129_proved :
    OpenCompliance.Controls.EnvironmentSegmentationSatisfied mediumEnvironmentSegmentationEvidence := by
  exact OpenCompliance.Controls.environmentSegmentationSatisfied_of_flags
    mediumEnvironmentSegmentationEvidence rfl rfl rfl

theorem exClaim104_proved :
    OpenCompliance.Controls.NarrowServiceAccountKeyCorridor mediumServiceAccountKeyEvidence := by
  exact OpenCompliance.Controls.narrowServiceAccountKeyCorridor_of_flags
    mediumServiceAccountKeyEvidence rfl rfl

theorem exClaim105_proved :
    OpenCompliance.Controls.ApprovedRegionBoundarySatisfied mediumApprovedRegionEvidence := by
  refine OpenCompliance.Controls.approvedRegionBoundarySatisfied_of_components mediumApprovedRegionEvidence ?_ ?_ ?_ ?_
  · simp [OpenCompliance.Controls.ApprovedRegionsDeclared, mediumApprovedRegionEvidence]
  · simp [OpenCompliance.Controls.ObservedRegionsDeclared, mediumApprovedRegionEvidence]
  · unfold OpenCompliance.Controls.ObservedRegionsWithinApproved mediumApprovedRegionEvidence
    native_decide
  · rfl

theorem exClaim106_proved :
    OpenCompliance.Controls.BackupSnapshotScheduleSatisfied mediumBackupSnapshotEvidence := by
  refine OpenCompliance.Controls.backupSnapshotScheduleSatisfied_of_components mediumBackupSnapshotEvidence ?_ ?_ ?_
  · rfl
  · unfold OpenCompliance.Controls.SnapshotFrequencyDeclared mediumBackupSnapshotEvidence
    decide
  · unfold OpenCompliance.Controls.ImmutableWindowDeclared mediumBackupSnapshotEvidence
    decide

theorem exClaim113_proved :
    OpenCompliance.Controls.DefaultBranchProtectionsEnforced mediumRepoBranchProtectionEvidence := by
  exact OpenCompliance.Controls.defaultBranchProtectionsEnforced_of_components
    mediumRepoBranchProtectionEvidence rfl (by decide) rfl rfl rfl

theorem exClaim114_proved :
    OpenCompliance.Controls.CiWorkflowPolicyConstrained mediumCiWorkflowPolicyEvidence := by
  exact OpenCompliance.Controls.ciWorkflowPolicyConstrained_of_flags
    mediumCiWorkflowPolicyEvidence rfl rfl rfl rfl

end OpenCompliance.Examples
