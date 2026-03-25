import OpenCompliance.Controls.Configuration
import OpenCompliance.Controls.Endpoint
import OpenCompliance.Controls.Network
import OpenCompliance.Controls.Patching

namespace OpenCompliance.Examples

def cyberBaselineNetworkBoundaryEvidence : OpenCompliance.Controls.NetworkBoundaryEvidence := {
  defaultDenyInbound := true
  declaredIngressPortsPresent := true
  undeclaredIngressPresent := false
  boundaryAttachedToIngressPath := true
  adminIngressRestricted := true
  approvedAdminSourceRangesDeclared := true
  unapprovedAdminIngressPresent := false
}

def cyberBaselineSecureConfigurationEvidence : OpenCompliance.Controls.SecureConfigurationEvidence := {
  baselineApplied := true
  insecureDefaultsPresent := false
  snapshotAgeDays := 7
}

def cyberBaselineSecurityUpdateEvidence : OpenCompliance.Controls.SecurityUpdateEvidence := {
  supportedVersionsOnly := true
  criticalOverdueCount := 0
  patchWindowDays := 7
}

def cyberBaselineMalwareProtectionEvidence : OpenCompliance.Controls.MalwareProtectionEvidence := {
  protectionEnabled := true
  signaturesCurrent := true
  tamperProtectionEnabled := true
}

theorem exClaim602_proved :
    OpenCompliance.Controls.DefaultDenyNetworkBoundarySatisfied cyberBaselineNetworkBoundaryEvidence := by
  exact OpenCompliance.Controls.defaultDenyNetworkBoundarySatisfied_of_flags
    cyberBaselineNetworkBoundaryEvidence rfl rfl rfl

theorem exClaim603_proved :
    OpenCompliance.Controls.SecureConfigurationBaselineSatisfied cyberBaselineSecureConfigurationEvidence := by
  exact OpenCompliance.Controls.secureConfigurationBaselineSatisfied_of_components
    cyberBaselineSecureConfigurationEvidence rfl rfl (by decide)

theorem exClaim604_proved :
    OpenCompliance.Controls.SupportedSecurityUpdatesCurrent cyberBaselineSecurityUpdateEvidence := by
  exact OpenCompliance.Controls.supportedSecurityUpdatesCurrent_of_components
    cyberBaselineSecurityUpdateEvidence rfl rfl (by decide)

theorem exClaim605_proved :
    OpenCompliance.Controls.MalwareProtectionBaselineSatisfied cyberBaselineMalwareProtectionEvidence := by
  exact OpenCompliance.Controls.malwareProtectionBaselineSatisfied_of_flags
    cyberBaselineMalwareProtectionEvidence rfl rfl rfl

end OpenCompliance.Examples
