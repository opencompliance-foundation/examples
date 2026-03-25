import LegalLean.Core
import LegalLean.Defeasible
import LegalLean.Solver
import OpenCompliance.Controls.Identity

namespace OpenCompliance.Controls.Typed

open LegalLean

structure RiskAcceptance where
  control_id : String
  justification : String
  approved_by : String
  expiry : Option String
deriving Repr, DecidableEq

structure IdentityAssessmentFacts where
  identity : OpenCompliance.Controls.IdentityEvidence
  riskAcceptance : Option RiskAcceptance
deriving Repr, DecidableEq

def riskAcceptanceAppliesTo
    (controlId : String)
    (r : RiskAcceptance) : Prop :=
  r.control_id = controlId

instance decidableRiskAcceptanceAppliesTo
    (controlId : String)
    (r : RiskAcceptance) :
    Decidable (riskAcceptanceAppliesTo controlId r) := by
  unfold riskAcceptanceAppliesTo
  infer_instance

def riskAcceptanceAppliesToBool
    (controlId : String)
    (r : RiskAcceptance) : Bool :=
  decide (riskAcceptanceAppliesTo controlId r)

def mfaControlId : String :=
  "oc.id-01"

def AdministrativeMfaObligationRule : LegalRule IdentityAssessmentFacts where
  id := "oc.id-01.obligation"
  description := "Scoped administrative identities must require MFA and enforce conditional access."
  modality := Deontic.obligatory
  priority := ⟨1, "OpenCompliance narrow identity corridor"⟩
  conclusion := fun facts =>
    OpenCompliance.Controls.AdministrativeMfaSatisfied facts.identity
  defeatedBy := ["oc.id-01.risk_acceptance"]

def AdministrativeMfaRiskAcceptanceRule : LegalRule IdentityAssessmentFacts where
  id := "oc.id-01.risk_acceptance"
  description := "A documented risk acceptance may defeat the narrow MFA obligation for the covered period."
  modality := Deontic.permitted
  priority := ⟨2, "Documented risk treatment exception"⟩
  conclusion := fun facts =>
    match facts.riskAcceptance with
    | some acceptance => riskAcceptanceAppliesTo mfaControlId acceptance
    | none => False
  defeatedBy := []
  applicable := fun facts =>
    match facts.riskAcceptance with
    | some acceptance => riskAcceptanceAppliesToBool mfaControlId acceptance
    | none => false

def AdministrativeMfaRiskAcceptanceDefeats : Defeats where
  defeater := AdministrativeMfaRiskAcceptanceRule.id
  defeated := AdministrativeMfaObligationRule.id
  reason := "A time-boxed risk acceptance explicitly covers the narrow administrative MFA obligation."
  strict := false

def narrowIdentityRuleCorpus : List (LegalRule IdentityAssessmentFacts) :=
  [AdministrativeMfaObligationRule, AdministrativeMfaRiskAcceptanceRule]

def identityAssessmentRiskAcceptance : RiskAcceptance := {
  control_id := mfaControlId
  justification := "Legacy administrative enclave still depends on staged MFA rollout."
  approved_by := "ciso@exampleco.test"
  expiry := some "2026-06-30"
}

def identityAssessmentWithGapAndAcceptance : IdentityAssessmentFacts := {
  identity := {
    mfaRequired := false
    conditionalAccessEnabled := false
  }
  riskAcceptance := some identityAssessmentRiskAcceptance
}

theorem riskAcceptanceDeclaresDefeat :
    AdministrativeMfaRiskAcceptanceDefeats.defeater =
      AdministrativeMfaRiskAcceptanceRule.id ∧
    AdministrativeMfaRiskAcceptanceDefeats.defeated =
      AdministrativeMfaObligationRule.id := by
  simp [AdministrativeMfaRiskAcceptanceDefeats, AdministrativeMfaRiskAcceptanceRule,
    AdministrativeMfaObligationRule]

theorem obligationListsRiskAcceptanceAsDefeater :
    AdministrativeMfaRiskAcceptanceRule.id ∈ AdministrativeMfaObligationRule.defeatedBy := by
  simp [AdministrativeMfaRiskAcceptanceRule, AdministrativeMfaObligationRule]

theorem mfaObligationIsDefeatedInCorpus :
    LegalLean.isDefeated AdministrativeMfaObligationRule narrowIdentityRuleCorpus = true := by
  simp [LegalLean.isDefeated, narrowIdentityRuleCorpus, AdministrativeMfaObligationRule,
    AdministrativeMfaRiskAcceptanceRule]

theorem solverPrefersRiskAcceptanceWhenApplicable :
    LegalLean.solve narrowIdentityRuleCorpus identityAssessmentWithGapAndAcceptance =
      FormalisationBoundary.formal
        (riskAcceptanceAppliesTo mfaControlId identityAssessmentRiskAcceptance) := by
  simp [LegalLean.solve, narrowIdentityRuleCorpus, identityAssessmentWithGapAndAcceptance,
    LegalLean.undefeatedRules, LegalLean.isDefeated, AdministrativeMfaObligationRule,
    AdministrativeMfaRiskAcceptanceRule, identityAssessmentRiskAcceptance, riskAcceptanceAppliesTo,
    riskAcceptanceAppliesToBool, mfaControlId]

end OpenCompliance.Controls.Typed
