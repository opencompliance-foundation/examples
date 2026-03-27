import LegalLean.Core
import OpenCompliance.Controls.Logging

namespace OpenCompliance.Controls.Typed

open LegalLean

def loggingCertificationBodyProxy : Authority :=
  Authority.accc

instance decidableAuditLoggingEnabled
    (e : OpenCompliance.Controls.AuditLoggingEvidence) :
    Decidable (OpenCompliance.Controls.AuditLoggingEnabled e) := by
  unfold OpenCompliance.Controls.AuditLoggingEnabled
  infer_instance

instance decidableRetentionWindowDeclared
    (e : OpenCompliance.Controls.AuditLoggingEvidence) :
    Decidable (OpenCompliance.Controls.RetentionWindowDeclared e) := by
  unfold OpenCompliance.Controls.RetentionWindowDeclared
  infer_instance

instance decidableNarrowAuditLoggingCorridor
    (e : OpenCompliance.Controls.AuditLoggingEvidence) :
    Decidable (OpenCompliance.Controls.NarrowAuditLoggingCorridor e) := by
  unfold OpenCompliance.Controls.NarrowAuditLoggingCorridor
  infer_instance

def typedAuditLoggingResult
    (e : OpenCompliance.Controls.AuditLoggingEvidence) :
    FormalisationBoundary (OpenCompliance.Controls.NarrowAuditLoggingCorridor e) :=
  if h : OpenCompliance.Controls.NarrowAuditLoggingCorridor e then
    FormalisationBoundary.formal h
  else
    FormalisationBoundary.boundary
      "Audit logging is not fully enabled in the scoped production environment."
      loggingCertificationBodyProxy

theorem typedAuditLoggingResult_enabled
    (e : OpenCompliance.Controls.AuditLoggingEvidence)
    (henabled : e.auditLoggingEnabled = true)
    (hretention : 0 < e.retentionDays) :
    ∃ proof,
      typedAuditLoggingResult e = FormalisationBoundary.formal proof := by
  have hs :
      OpenCompliance.Controls.NarrowAuditLoggingCorridor e :=
    OpenCompliance.Controls.narrowAuditLoggingCorridor_of_components
      e
      (OpenCompliance.Controls.auditLoggingEnabled_of_flag e henabled)
      (OpenCompliance.Controls.retentionWindowDeclared_of_positive e hretention)
  refine ⟨hs, ?_⟩
  unfold typedAuditLoggingResult
  simp [hs]

theorem typedAuditLoggingResult_boundary
    (e : OpenCompliance.Controls.AuditLoggingEvidence)
    (h : ¬ OpenCompliance.Controls.NarrowAuditLoggingCorridor e) :
    ∃ reason authority,
      typedAuditLoggingResult e = FormalisationBoundary.boundary reason authority := by
  refine ⟨"Audit logging is not fully enabled in the scoped production environment.",
    loggingCertificationBodyProxy, ?_⟩
  unfold typedAuditLoggingResult
  simp [h, loggingCertificationBodyProxy]

end OpenCompliance.Controls.Typed
