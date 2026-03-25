namespace OpenCompliance.Controls

structure AuditLoggingEvidence where
  auditLoggingEnabled : Bool
  retentionDays : Nat
deriving Repr, DecidableEq

structure CentralMonitoringEvidence where
  centralSinkConfigured : Bool
  scopedAssetsForwarded : Bool
  alertRulesEnabled : Bool
deriving Repr, DecidableEq

def AuditLoggingEnabled (e : AuditLoggingEvidence) : Prop :=
  e.auditLoggingEnabled = true

def RetentionWindowDeclared (e : AuditLoggingEvidence) : Prop :=
  0 < e.retentionDays

def CentralSinkConfigured (e : CentralMonitoringEvidence) : Prop :=
  e.centralSinkConfigured = true

def ScopedAssetsForwarded (e : CentralMonitoringEvidence) : Prop :=
  e.scopedAssetsForwarded = true

def AlertRulesEnabled (e : CentralMonitoringEvidence) : Prop :=
  e.alertRulesEnabled = true

def NarrowAuditLoggingCorridor (e : AuditLoggingEvidence) : Prop :=
  AuditLoggingEnabled e ∧ RetentionWindowDeclared e

def CentralizedMonitoringSatisfied (e : CentralMonitoringEvidence) : Prop :=
  CentralSinkConfigured e ∧ ScopedAssetsForwarded e ∧ AlertRulesEnabled e

theorem auditLoggingEnabled_of_flag
    (e : AuditLoggingEvidence)
    (henabled : e.auditLoggingEnabled = true) :
    AuditLoggingEnabled e := by
  exact henabled

theorem retentionWindowDeclared_of_positive
    (e : AuditLoggingEvidence)
    (hretention : 0 < e.retentionDays) :
    RetentionWindowDeclared e := by
  exact hretention

theorem narrowAuditLoggingCorridor_of_components
    (e : AuditLoggingEvidence)
    (henabled : AuditLoggingEnabled e)
    (hretention : RetentionWindowDeclared e) :
    NarrowAuditLoggingCorridor e := by
  exact And.intro henabled hretention

theorem centralSinkConfigured_of_flag
    (e : CentralMonitoringEvidence)
    (hconfigured : e.centralSinkConfigured = true) :
    CentralSinkConfigured e := by
  exact hconfigured

theorem scopedAssetsForwarded_of_flag
    (e : CentralMonitoringEvidence)
    (hforwarded : e.scopedAssetsForwarded = true) :
    ScopedAssetsForwarded e := by
  exact hforwarded

theorem alertRulesEnabled_of_flag
    (e : CentralMonitoringEvidence)
    (henabled : e.alertRulesEnabled = true) :
    AlertRulesEnabled e := by
  exact henabled

theorem centralizedMonitoringSatisfied_of_flags
    (e : CentralMonitoringEvidence)
    (hconfigured : e.centralSinkConfigured = true)
    (hforwarded : e.scopedAssetsForwarded = true)
    (henabled : e.alertRulesEnabled = true) :
    CentralizedMonitoringSatisfied e := by
  exact And.intro hconfigured (And.intro hforwarded henabled)

end OpenCompliance.Controls
