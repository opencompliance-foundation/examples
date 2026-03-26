import OpenCompliance.Controls.Identity
import OpenCompliance.Controls.Logging

namespace OpenCompliance.Examples

def bundleId : String :=
  "exampleco-minimal-bundle-2026-03-24"

def minimalIdentityEvidence : OpenCompliance.Controls.IdentityEvidence := {
  mfaRequired := true
  conditionalAccessEnabled := true
}

def minimalAuditLoggingEvidence : OpenCompliance.Controls.AuditLoggingEvidence := {
  auditLoggingEnabled := true
  retentionDays := 90
}

theorem exClaim001_proved :
    OpenCompliance.Controls.AdministrativeMfaSatisfied minimalIdentityEvidence := by
  constructor <;> rfl

theorem exClaim002_proved :
    OpenCompliance.Controls.AuditLoggingEnabled minimalAuditLoggingEvidence := by
  rfl

theorem exClaim002_supportingRetentionDeclared :
    OpenCompliance.Controls.RetentionWindowDeclared minimalAuditLoggingEvidence := by
  unfold OpenCompliance.Controls.RetentionWindowDeclared minimalAuditLoggingEvidence
  decide

theorem exClaim002_supportingCorridor :
    OpenCompliance.Controls.NarrowAuditLoggingCorridor minimalAuditLoggingEvidence := by
  exact And.intro exClaim002_proved exClaim002_supportingRetentionDeclared

end OpenCompliance.Examples
