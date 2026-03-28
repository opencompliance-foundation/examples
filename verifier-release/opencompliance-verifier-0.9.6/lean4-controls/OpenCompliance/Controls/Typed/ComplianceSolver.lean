import Lean
import LegalLean.Core
import LegalLean.Solver
import OpenCompliance.Controls.Identity
import OpenCompliance.Controls.Logging
import OpenCompliance.Controls.Typed.DiscretionaryTerms
import OpenCompliance.Controls.Typed.RiskAcceptance
import OpenCompliance.Controls.Typed.TypedIdentity
import OpenCompliance.Controls.Typed.TypedLogging

namespace OpenCompliance.Controls.Typed

open LegalLean

inductive MinimalClaimId where
  | ex001
  | ex002
  | ex003
  | ex004
  | ex005
  deriving Repr, BEq, DecidableEq

structure MinimalComplianceEvidence where
  target : MinimalClaimId
  identity : OpenCompliance.Controls.IdentityEvidence
  logging : OpenCompliance.Controls.AuditLoggingEvidence
  trainingAttestationExists : Bool
  policyAdequacyRequiresHumanReview : Bool
  restoreEvidenceAttached : Bool
  riskAcceptance : Option RiskAcceptance
deriving Repr, DecidableEq

def claimIs (facts : MinimalComplianceEvidence) (claim : MinimalClaimId) : Bool :=
  facts.target == claim

def trainingAttestationExists (facts : MinimalComplianceEvidence) : Prop :=
  facts.trainingAttestationExists = true

def policyAdequacySatisfied (facts : MinimalComplianceEvidence) : Prop :=
  facts.policyAdequacyRequiresHumanReview = false

def restoreEvidenceAttached (facts : MinimalComplianceEvidence) : Prop :=
  facts.restoreEvidenceAttached = true

def ex001_mfaRule : LegalRule MinimalComplianceEvidence where
  id := "EX-CLAIM-001"
  description := "Administrative identities require MFA in the scoped production environment."
  modality := Deontic.obligatory
  priority := ⟨1, "OpenCompliance minimal corridor"⟩
  conclusion := fun facts => OpenCompliance.Controls.AdministrativeMfaSatisfied facts.identity
  defeatedBy := ["EX-CLAIM-001-RISK-ACCEPTANCE"]
  applicable := fun facts => claimIs facts MinimalClaimId.ex001

def ex001_mfaRiskAcceptanceRule : LegalRule MinimalComplianceEvidence where
  id := "EX-CLAIM-001-RISK-ACCEPTANCE"
  description := "A risk acceptance covers the narrow administrative MFA claim."
  modality := Deontic.permitted
  priority := ⟨2, "Documented risk treatment exception"⟩
  conclusion := fun facts =>
    match facts.riskAcceptance with
    | some acceptance => riskAcceptanceAppliesTo mfaControlId acceptance
    | none => False
  defeatedBy := []
  applicable := fun facts =>
    claimIs facts MinimalClaimId.ex001 &&
      match facts.riskAcceptance with
      | some acceptance => riskAcceptanceAppliesToBool mfaControlId acceptance
      | none => false

def ex002_loggingRule : LegalRule MinimalComplianceEvidence where
  id := "EX-CLAIM-002"
  description := "Audit logging is enabled for the scoped production stack."
  modality := Deontic.obligatory
  priority := ⟨1, "OpenCompliance minimal corridor"⟩
  conclusion := fun facts => OpenCompliance.Controls.NarrowAuditLoggingCorridor facts.logging
  defeatedBy := []
  applicable := fun facts => claimIs facts MinimalClaimId.ex002

def minimalComplianceRules : List (LegalRule MinimalComplianceEvidence) :=
  [ex001_mfaRule, ex001_mfaRiskAcceptanceRule, ex002_loggingRule]

def minimalClaim001Facts : MinimalComplianceEvidence := {
  target := MinimalClaimId.ex001
  identity := {
    mfaRequired := true
    conditionalAccessEnabled := true
  }
  logging := {
    auditLoggingEnabled := true
    retentionDays := 90
  }
  trainingAttestationExists := true
  policyAdequacyRequiresHumanReview := true
  restoreEvidenceAttached := false
  riskAcceptance := none
}

def minimalClaim002Facts : MinimalComplianceEvidence := {
  target := MinimalClaimId.ex002
  identity := minimalClaim001Facts.identity
  logging := minimalClaim001Facts.logging
  trainingAttestationExists := true
  policyAdequacyRequiresHumanReview := true
  restoreEvidenceAttached := false
  riskAcceptance := none
}

def minimalClaim003Facts : MinimalComplianceEvidence := {
  target := MinimalClaimId.ex003
  identity := minimalClaim001Facts.identity
  logging := minimalClaim001Facts.logging
  trainingAttestationExists := true
  policyAdequacyRequiresHumanReview := true
  restoreEvidenceAttached := false
  riskAcceptance := none
}

def minimalClaim004Facts : MinimalComplianceEvidence := {
  target := MinimalClaimId.ex004
  identity := minimalClaim001Facts.identity
  logging := minimalClaim001Facts.logging
  trainingAttestationExists := true
  policyAdequacyRequiresHumanReview := true
  restoreEvidenceAttached := false
  riskAcceptance := none
}

def minimalClaim005Facts : MinimalComplianceEvidence := {
  target := MinimalClaimId.ex005
  identity := minimalClaim001Facts.identity
  logging := minimalClaim001Facts.logging
  trainingAttestationExists := true
  policyAdequacyRequiresHumanReview := true
  restoreEvidenceAttached := false
  riskAcceptance := none
}

def solveMinimalClaim
    (facts : MinimalComplianceEvidence) :
    FormalisationBoundary Prop :=
  LegalLean.solve minimalComplianceRules facts

theorem ex001PrimaryRuleApplies :
    ex001_mfaRule.applicable minimalClaim001Facts = true := by
  unfold ex001_mfaRule claimIs minimalClaim001Facts
  native_decide

theorem ex001RiskAcceptanceRuleDoesNotApply :
    ex001_mfaRiskAcceptanceRule.applicable minimalClaim001Facts = false := by
  simp [ex001_mfaRiskAcceptanceRule, claimIs, minimalClaim001Facts,
    riskAcceptanceAppliesToBool, mfaControlId]

theorem ex002LoggingRuleApplies :
    ex002_loggingRule.applicable minimalClaim002Facts = true := by
  unfold ex002_loggingRule claimIs minimalClaim002Facts minimalClaim001Facts
  native_decide

theorem ex001PrimaryRuleDoesNotApplyToClaim002 :
    ex001_mfaRule.applicable minimalClaim002Facts = false := by
  unfold ex001_mfaRule claimIs minimalClaim002Facts minimalClaim001Facts
  native_decide

theorem ex001PrimaryRuleDoesNotApplyToClaim003 :
    ex001_mfaRule.applicable minimalClaim003Facts = false := by
  unfold ex001_mfaRule claimIs minimalClaim003Facts minimalClaim001Facts
  native_decide

theorem ex001PrimaryRuleDoesNotApplyToClaim004 :
    ex001_mfaRule.applicable minimalClaim004Facts = false := by
  unfold ex001_mfaRule claimIs minimalClaim004Facts minimalClaim001Facts
  native_decide

theorem ex001PrimaryRuleDoesNotApplyToClaim005 :
    ex001_mfaRule.applicable minimalClaim005Facts = false := by
  unfold ex001_mfaRule claimIs minimalClaim005Facts minimalClaim001Facts
  native_decide

theorem ex001RiskAcceptanceRuleDoesNotApplyToClaim003 :
    ex001_mfaRiskAcceptanceRule.applicable minimalClaim003Facts = false := by
  simp [ex001_mfaRiskAcceptanceRule, claimIs, minimalClaim003Facts, minimalClaim001Facts,
    riskAcceptanceAppliesToBool, mfaControlId]

theorem ex001RiskAcceptanceRuleDoesNotApplyToClaim004 :
    ex001_mfaRiskAcceptanceRule.applicable minimalClaim004Facts = false := by
  simp [ex001_mfaRiskAcceptanceRule, claimIs, minimalClaim004Facts, minimalClaim001Facts,
    riskAcceptanceAppliesToBool, mfaControlId]

theorem ex001RiskAcceptanceRuleDoesNotApplyToClaim005 :
    ex001_mfaRiskAcceptanceRule.applicable minimalClaim005Facts = false := by
  simp [ex001_mfaRiskAcceptanceRule, claimIs, minimalClaim005Facts, minimalClaim001Facts,
    riskAcceptanceAppliesToBool, mfaControlId]

theorem ex002LoggingRuleDoesNotApplyToClaim001 :
    ex002_loggingRule.applicable minimalClaim001Facts = false := by
  unfold ex002_loggingRule claimIs minimalClaim001Facts
  native_decide

theorem ex002LoggingRuleDoesNotApplyToClaim003 :
    ex002_loggingRule.applicable minimalClaim003Facts = false := by
  unfold ex002_loggingRule claimIs minimalClaim003Facts minimalClaim001Facts
  native_decide

theorem ex002LoggingRuleDoesNotApplyToClaim004 :
    ex002_loggingRule.applicable minimalClaim004Facts = false := by
  unfold ex002_loggingRule claimIs minimalClaim004Facts minimalClaim001Facts
  native_decide

theorem ex002LoggingRuleDoesNotApplyToClaim005 :
    ex002_loggingRule.applicable minimalClaim005Facts = false := by
  unfold ex002_loggingRule claimIs minimalClaim005Facts minimalClaim001Facts
  native_decide

def ex001_mfaRule_isolated : LegalRule MinimalComplianceEvidence :=
  { ex001_mfaRule with defeatedBy := [] }

theorem solveMinimalClaim001SingleRuleCorpus :
    LegalLean.solve [ex001_mfaRule_isolated] minimalClaim001Facts =
      FormalisationBoundary.formal
        (OpenCompliance.Controls.AdministrativeMfaSatisfied minimalClaim001Facts.identity) := by
  apply LegalLean.solve_single_undefeated_rule_is_formal
  · simp [ex001_mfaRule_isolated, ex001_mfaRule]
  · exact ex001PrimaryRuleApplies

theorem solveMinimalClaim002SingleRuleCorpus :
    LegalLean.solve [ex002_loggingRule] minimalClaim002Facts =
      FormalisationBoundary.formal
        (OpenCompliance.Controls.NarrowAuditLoggingCorridor minimalClaim002Facts.logging) := by
  apply LegalLean.solve_single_undefeated_rule_is_formal
  · simp [ex002_loggingRule]
  · exact ex002LoggingRuleApplies

theorem solveMinimalClaim001_exact :
    solveMinimalClaim minimalClaim001Facts =
      FormalisationBoundary.formal
        (OpenCompliance.Controls.AdministrativeMfaSatisfied minimalClaim001Facts.identity) := by
  have hApplicable :
      List.filter (fun r => r.applicable minimalClaim001Facts) minimalComplianceRules =
        [ex001_mfaRule] := by
    simp [minimalComplianceRules, ex001PrimaryRuleApplies,
      ex001RiskAcceptanceRuleDoesNotApply, ex002LoggingRuleDoesNotApplyToClaim001]
  unfold solveMinimalClaim LegalLean.solve
  rw [hApplicable]
  simp [LegalLean.undefeatedRules, LegalLean.isDefeated, ex001_mfaRule]

theorem solveMinimalClaim002_exact :
    solveMinimalClaim minimalClaim002Facts =
      FormalisationBoundary.formal
        (OpenCompliance.Controls.NarrowAuditLoggingCorridor minimalClaim002Facts.logging) := by
  have hRiskDoesNotApply :
      ex001_mfaRiskAcceptanceRule.applicable minimalClaim002Facts = false := by
    simp [ex001_mfaRiskAcceptanceRule, claimIs, minimalClaim002Facts, minimalClaim001Facts,
      riskAcceptanceAppliesToBool, mfaControlId]
  have hApplicable :
      List.filter (fun r => r.applicable minimalClaim002Facts) minimalComplianceRules =
        [ex002_loggingRule] := by
    simp [minimalComplianceRules, ex001PrimaryRuleDoesNotApplyToClaim002,
      hRiskDoesNotApply, ex002LoggingRuleApplies]
  unfold solveMinimalClaim LegalLean.solve
  rw [hApplicable]
  simp [LegalLean.undefeatedRules, LegalLean.isDefeated, ex002_loggingRule]

def noRuleBoundary : FormalisationBoundary Prop :=
  FormalisationBoundary.boundary
    "No rules in corpus — human authority must determine applicable law"
    Authority.irsTaxCourt

theorem solveMinimalClaim003_exact :
    solveMinimalClaim minimalClaim003Facts = noRuleBoundary := by
  have hApplicable :
      List.filter (fun r => r.applicable minimalClaim003Facts) minimalComplianceRules = [] := by
    simp [minimalComplianceRules, ex001PrimaryRuleDoesNotApplyToClaim003,
      ex001RiskAcceptanceRuleDoesNotApplyToClaim003, ex002LoggingRuleDoesNotApplyToClaim003]
  unfold solveMinimalClaim noRuleBoundary LegalLean.solve
  simp [hApplicable]

theorem solveMinimalClaim004_exact :
    solveMinimalClaim minimalClaim004Facts = noRuleBoundary := by
  have hApplicable :
      List.filter (fun r => r.applicable minimalClaim004Facts) minimalComplianceRules = [] := by
    simp [minimalComplianceRules, ex001PrimaryRuleDoesNotApplyToClaim004,
      ex001RiskAcceptanceRuleDoesNotApplyToClaim004, ex002LoggingRuleDoesNotApplyToClaim004]
  unfold solveMinimalClaim noRuleBoundary LegalLean.solve
  simp [hApplicable]

theorem solveMinimalClaim005_exact :
    solveMinimalClaim minimalClaim005Facts = noRuleBoundary := by
  have hApplicable :
      List.filter (fun r => r.applicable minimalClaim005Facts) minimalComplianceRules = [] := by
    simp [minimalComplianceRules, ex001PrimaryRuleDoesNotApplyToClaim005,
      ex001RiskAcceptanceRuleDoesNotApplyToClaim005, ex002LoggingRuleDoesNotApplyToClaim005]
  unfold solveMinimalClaim noRuleBoundary LegalLean.solve
  simp [hApplicable]

theorem solveMinimalClaim003_boundary :
    ∃ reason authority,
      solveMinimalClaim minimalClaim003Facts =
        FormalisationBoundary.boundary reason authority := by
  unfold solveMinimalClaim
  simp [LegalLean.solve, minimalComplianceRules, minimalClaim003Facts, claimIs,
    ex001_mfaRule, ex001_mfaRiskAcceptanceRule, ex002_loggingRule]
  exact ⟨_, _, rfl⟩

theorem solveMinimalClaim004_boundary :
    ∃ reason authority,
      solveMinimalClaim minimalClaim004Facts =
        FormalisationBoundary.boundary reason authority := by
  unfold solveMinimalClaim
  simp [LegalLean.solve, minimalComplianceRules, minimalClaim004Facts, claimIs,
    ex001_mfaRule, ex001_mfaRiskAcceptanceRule, ex002_loggingRule]
  exact ⟨_, _, rfl⟩

theorem solveMinimalClaim005_boundary :
    ∃ reason authority,
      solveMinimalClaim minimalClaim005Facts =
        FormalisationBoundary.boundary reason authority := by
  unfold solveMinimalClaim
  simp [LegalLean.solve, minimalComplianceRules, minimalClaim005Facts, claimIs,
    ex001_mfaRule, ex001_mfaRiskAcceptanceRule, ex002_loggingRule]
  exact ⟨_, _, rfl⟩

theorem minimalComplianceSolverCoverage :
    ex001_mfaRule.applicable minimalClaim001Facts = true ∧
      ex001_mfaRiskAcceptanceRule.applicable minimalClaim001Facts = false ∧
      ex002_loggingRule.applicable minimalClaim002Facts = true ∧
      ex001_mfaRule.applicable minimalClaim002Facts = false := by
  exact And.intro
    ex001PrimaryRuleApplies
      (And.intro
        ex001RiskAcceptanceRuleDoesNotApply
      (And.intro ex002LoggingRuleApplies ex001PrimaryRuleDoesNotApplyToClaim002))

theorem minimalComplianceSolverExpectedBoundaries :
    solveMinimalClaim minimalClaim001Facts =
        FormalisationBoundary.formal
          (OpenCompliance.Controls.AdministrativeMfaSatisfied minimalClaim001Facts.identity) ∧
      solveMinimalClaim minimalClaim002Facts =
        FormalisationBoundary.formal
          (OpenCompliance.Controls.NarrowAuditLoggingCorridor minimalClaim002Facts.logging) ∧
      solveMinimalClaim minimalClaim003Facts = noRuleBoundary ∧
      solveMinimalClaim minimalClaim004Facts = noRuleBoundary ∧
      solveMinimalClaim minimalClaim005Facts = noRuleBoundary := by
  exact And.intro
    solveMinimalClaim001_exact
    (And.intro
      solveMinimalClaim002_exact
      (And.intro
        solveMinimalClaim003_exact
        (And.intro solveMinimalClaim004_exact solveMinimalClaim005_exact)))

inductive MinimalClaimSlot where
  | identity
  | logging
  | training
  | policy
  | restore
  deriving Repr, BEq, DecidableEq

structure MinimalRuntimeInputs where
  identity : Option OpenCompliance.Controls.IdentityEvidence
  identityFresh : Bool
  logging : Option OpenCompliance.Controls.AuditLoggingEvidence
  loggingFresh : Bool
  trainingAttestationExists : Bool
  trainingAttestationSigned : Bool
  trainingFresh : Bool
  policyAdequacyRequiresHumanReview : Bool
  restoreEvidenceAttached : Bool
  restoreTestCompleted : Bool
  restoreFresh : Bool
  riskAcceptance : Option RiskAcceptance
deriving Repr, DecidableEq

inductive RuntimeVerdict where
  | proved
  | attested
  | failed
  | staleEvidence
  | judgmentRequired
  | evidenceMissing
  deriving Repr, BEq, DecidableEq

structure RuntimeClaimDecision where
  slot : MinimalClaimSlot
  verdict : RuntimeVerdict
  reason : String
  solverBoundaryTag : String
  typedBoundaryTag : String
deriving Repr, DecidableEq

def runtimeVerdictLabel : RuntimeVerdict → String
  | RuntimeVerdict.proved => "proved"
  | RuntimeVerdict.attested => "attested"
  | RuntimeVerdict.failed => "failed"
  | RuntimeVerdict.staleEvidence => "stale_evidence"
  | RuntimeVerdict.judgmentRequired => "judgment_required"
  | RuntimeVerdict.evidenceMissing => "evidence_missing"

def minimalClaimSlotLabel : MinimalClaimSlot → String
  | MinimalClaimSlot.identity => "identity"
  | MinimalClaimSlot.logging => "logging"
  | MinimalClaimSlot.training => "training"
  | MinimalClaimSlot.policy => "policy"
  | MinimalClaimSlot.restore => "restore"

def boundaryTag {P : Sort _} : FormalisationBoundary P → String
  | FormalisationBoundary.formal _ => "formal"
  | FormalisationBoundary.boundary _ _ => "boundary"
  | FormalisationBoundary.mixed _ _ => "mixed"

def defaultIdentityEvidence : OpenCompliance.Controls.IdentityEvidence := {
  mfaRequired := false
  conditionalAccessEnabled := false
}

def defaultLoggingEvidence : OpenCompliance.Controls.AuditLoggingEvidence := {
  auditLoggingEnabled := false
  retentionDays := 0
}

def runtimeFactsForTarget
    (inputs : MinimalRuntimeInputs)
    (target : MinimalClaimId) :
    MinimalComplianceEvidence := {
  target := target
  identity := inputs.identity.getD defaultIdentityEvidence
  logging := inputs.logging.getD defaultLoggingEvidence
  trainingAttestationExists := inputs.trainingAttestationExists
  policyAdequacyRequiresHumanReview := inputs.policyAdequacyRequiresHumanReview
  restoreEvidenceAttached := inputs.restoreEvidenceAttached
  riskAcceptance := inputs.riskAcceptance
}

def runtimeTypedIdentityEvidence
    (inputs : MinimalRuntimeInputs) :
    TypedIdentityEvidence := {
  base := inputs.identity.getD defaultIdentityEvidence
  trainingAttestationExists := inputs.trainingAttestationExists
  trainingAttestationSigned := inputs.trainingAttestationSigned
}

def RestoreTestAttestationSatisfied
    (inputs : MinimalRuntimeInputs) : Prop :=
  inputs.restoreEvidenceAttached = true ∧
    inputs.restoreTestCompleted = true

instance decidableRestoreTestAttestationSatisfied
    (inputs : MinimalRuntimeInputs) :
    Decidable (RestoreTestAttestationSatisfied inputs) := by
  unfold RestoreTestAttestationSatisfied
  infer_instance

def typedRestoreAttestationResult
    (inputs : MinimalRuntimeInputs) :
    FormalisationBoundary (RestoreTestAttestationSatisfied inputs) :=
  if _h : RestoreTestAttestationSatisfied inputs then
    FormalisationBoundary.boundary
      "Restore testing is documentary evidence and remains attestation-backed even when present."
      Authority.accc
  else if inputs.restoreEvidenceAttached = false then
    FormalisationBoundary.boundary
      "No signed restore-test attestation is present for the recovery corridor."
      Authority.accc
  else
    FormalisationBoundary.boundary
      "The restore-test attestation is attached but does not declare a completed in-scope exercise."
      Authority.accc

def identityDecision
    (inputs : MinimalRuntimeInputs) :
    RuntimeClaimDecision :=
  match inputs.identity with
  | none =>
      {
        slot := MinimalClaimSlot.identity
        verdict := RuntimeVerdict.evidenceMissing
        reason := "No typed identity provider export is attached to the corridor."
        solverBoundaryTag := "boundary"
        typedBoundaryTag := "boundary"
      }
  | some identity =>
      if inputs.identityFresh = false then
        {
          slot := MinimalClaimSlot.identity
          verdict := RuntimeVerdict.staleEvidence
          reason := "The identity provider export exists, but its freshness window expired before this verification run."
          solverBoundaryTag := "boundary"
          typedBoundaryTag := "boundary"
        }
      else
        let solverBoundary := solveMinimalClaim (runtimeFactsForTarget inputs MinimalClaimId.ex001)
        let typedBoundary := typedAdministrativeMfaResult identity
        match typedBoundary with
        | FormalisationBoundary.formal _ =>
            {
              slot := MinimalClaimSlot.identity
              verdict := RuntimeVerdict.proved
              reason := "The typed identity corridor and LegalLean solver both admit the administrative MFA claim."
              solverBoundaryTag := boundaryTag solverBoundary
              typedBoundaryTag := boundaryTag typedBoundary
            }
        | FormalisationBoundary.boundary reason _ =>
            {
              slot := MinimalClaimSlot.identity
              verdict := RuntimeVerdict.failed
              reason := reason
              solverBoundaryTag := boundaryTag solverBoundary
              typedBoundaryTag := boundaryTag typedBoundary
            }
        | FormalisationBoundary.mixed _ humanPart =>
            {
              slot := MinimalClaimSlot.identity
              verdict := RuntimeVerdict.failed
              reason := humanPart
              solverBoundaryTag := boundaryTag solverBoundary
              typedBoundaryTag := boundaryTag typedBoundary
            }

def loggingDecision
    (inputs : MinimalRuntimeInputs) :
    RuntimeClaimDecision :=
  match inputs.logging with
  | none =>
      {
        slot := MinimalClaimSlot.logging
        verdict := RuntimeVerdict.evidenceMissing
        reason := "No typed audit logging export is attached to the corridor."
        solverBoundaryTag := "boundary"
        typedBoundaryTag := "boundary"
      }
  | some logging =>
      if inputs.loggingFresh = false then
        {
          slot := MinimalClaimSlot.logging
          verdict := RuntimeVerdict.staleEvidence
          reason := "The audit-logging export exists, but its freshness window expired before this verification run."
          solverBoundaryTag := "boundary"
          typedBoundaryTag := "boundary"
        }
      else
        let solverBoundary := solveMinimalClaim (runtimeFactsForTarget inputs MinimalClaimId.ex002)
        let typedBoundary := typedAuditLoggingResult logging
        match typedBoundary with
        | FormalisationBoundary.formal _ =>
            {
              slot := MinimalClaimSlot.logging
              verdict := RuntimeVerdict.proved
              reason := "The typed logging corridor and LegalLean solver both admit the audit-logging claim."
              solverBoundaryTag := boundaryTag solverBoundary
              typedBoundaryTag := boundaryTag typedBoundary
            }
        | FormalisationBoundary.boundary reason _ =>
            {
              slot := MinimalClaimSlot.logging
              verdict := RuntimeVerdict.failed
              reason := reason
              solverBoundaryTag := boundaryTag solverBoundary
              typedBoundaryTag := boundaryTag typedBoundary
            }
        | FormalisationBoundary.mixed _ humanPart =>
            {
              slot := MinimalClaimSlot.logging
              verdict := RuntimeVerdict.failed
              reason := humanPart
              solverBoundaryTag := boundaryTag solverBoundary
              typedBoundaryTag := boundaryTag typedBoundary
            }

def trainingDecision
    (inputs : MinimalRuntimeInputs) :
    RuntimeClaimDecision :=
  let typedBoundary := typedTrainingAttestationResult (runtimeTypedIdentityEvidence inputs)
  if inputs.trainingAttestationExists = false then
    {
      slot := MinimalClaimSlot.training
      verdict := RuntimeVerdict.evidenceMissing
      reason := "No signed training attestation is present for the identity corridor."
      solverBoundaryTag := "boundary"
      typedBoundaryTag := boundaryTag typedBoundary
    }
  else if inputs.trainingFresh = false then
    {
      slot := MinimalClaimSlot.training
      verdict := RuntimeVerdict.staleEvidence
      reason := "The training attestation exists, but its freshness window expired before this verification run."
      solverBoundaryTag := "boundary"
      typedBoundaryTag := boundaryTag typedBoundary
    }
  else if inputs.trainingAttestationSigned = true then
    {
      slot := MinimalClaimSlot.training
      verdict := RuntimeVerdict.attested
      reason := "The training claim is present and signed, but remains documentary evidence requiring human determination."
      solverBoundaryTag := "boundary"
      typedBoundaryTag := boundaryTag typedBoundary
    }
  else
    {
      slot := MinimalClaimSlot.training
      verdict := RuntimeVerdict.failed
      reason := "The training attestation exists but is not signed by a named human actor."
      solverBoundaryTag := "boundary"
      typedBoundaryTag := boundaryTag typedBoundary
    }

def policyDecision
    (_inputs : MinimalRuntimeInputs) :
    RuntimeClaimDecision :=
  let typedBoundary := overallPolicySuiteAdequacyBoundary
  {
    slot := MinimalClaimSlot.policy
    verdict := RuntimeVerdict.judgmentRequired
    reason := "Whole-program policy adequacy remains outside the machine-proof corridor."
    solverBoundaryTag := "boundary"
    typedBoundaryTag := boundaryTag typedBoundary
  }

def restoreDecision
    (inputs : MinimalRuntimeInputs) :
    RuntimeClaimDecision :=
  let typedBoundary := typedRestoreAttestationResult inputs
  if inputs.restoreEvidenceAttached = false then
    {
      slot := MinimalClaimSlot.restore
      verdict := RuntimeVerdict.evidenceMissing
      reason := "No signed restore-test attestation is present for the recovery corridor."
      solverBoundaryTag := "boundary"
      typedBoundaryTag := boundaryTag typedBoundary
    }
  else if inputs.restoreFresh = false then
    {
      slot := MinimalClaimSlot.restore
      verdict := RuntimeVerdict.staleEvidence
      reason := "The restore-test attestation exists, but its freshness window expired before this verification run."
      solverBoundaryTag := "boundary"
      typedBoundaryTag := boundaryTag typedBoundary
    }
  else if inputs.restoreTestCompleted = true then
    {
      slot := MinimalClaimSlot.restore
      verdict := RuntimeVerdict.attested
      reason := "The restore-test attestation is present and declares a completed exercise, but remains documentary evidence."
      solverBoundaryTag := "boundary"
      typedBoundaryTag := boundaryTag typedBoundary
    }
  else
    {
      slot := MinimalClaimSlot.restore
      verdict := RuntimeVerdict.failed
      reason := "The restore-test attestation is attached but does not declare a completed in-scope exercise."
      solverBoundaryTag := "boundary"
      typedBoundaryTag := boundaryTag typedBoundary
    }

def minimalRuntimeDecisions
    (inputs : MinimalRuntimeInputs) :
    List RuntimeClaimDecision :=
  [
    identityDecision inputs,
    loggingDecision inputs,
    trainingDecision inputs,
    policyDecision inputs,
    restoreDecision inputs
  ]

def minimalRuntimeInputs : MinimalRuntimeInputs := {
  identity := some minimalClaim001Facts.identity
  identityFresh := true
  logging := some minimalClaim001Facts.logging
  loggingFresh := true
  trainingAttestationExists := true
  trainingAttestationSigned := true
  trainingFresh := true
  policyAdequacyRequiresHumanReview := true
  restoreEvidenceAttached := false
  restoreTestCompleted := false
  restoreFresh := true
  riskAcceptance := none
}

theorem minimalRuntimeIdentityDecision_proved :
    (identityDecision minimalRuntimeInputs).verdict = RuntimeVerdict.proved := by
  native_decide

theorem minimalRuntimeLoggingDecision_proved :
    (loggingDecision minimalRuntimeInputs).verdict = RuntimeVerdict.proved := by
  native_decide

theorem minimalRuntimeTrainingDecision_attested :
    (trainingDecision minimalRuntimeInputs).verdict = RuntimeVerdict.attested := by
  native_decide

theorem minimalRuntimePolicyDecision_requiresHumanJudgment :
    (policyDecision minimalRuntimeInputs).verdict = RuntimeVerdict.judgmentRequired := by
  native_decide

theorem minimalRuntimeRestoreDecision_missing :
    (restoreDecision minimalRuntimeInputs).verdict = RuntimeVerdict.evidenceMissing := by
  native_decide

theorem minimalRuntimeDecisionCoverage :
    minimalRuntimeDecisions minimalRuntimeInputs =
      [
        {
          slot := MinimalClaimSlot.identity
          verdict := RuntimeVerdict.proved
          reason := "The typed identity corridor and LegalLean solver both admit the administrative MFA claim."
          solverBoundaryTag := "formal"
          typedBoundaryTag := "formal"
        },
        {
          slot := MinimalClaimSlot.logging
          verdict := RuntimeVerdict.proved
          reason := "The typed logging corridor and LegalLean solver both admit the audit-logging claim."
          solverBoundaryTag := "formal"
          typedBoundaryTag := "formal"
        },
        {
          slot := MinimalClaimSlot.training
          verdict := RuntimeVerdict.attested
          reason := "The training claim is present and signed, but remains documentary evidence requiring human determination."
          solverBoundaryTag := "boundary"
          typedBoundaryTag := "boundary"
        },
        {
          slot := MinimalClaimSlot.policy
          verdict := RuntimeVerdict.judgmentRequired
          reason := "Whole-program policy adequacy remains outside the machine-proof corridor."
          solverBoundaryTag := "boundary"
          typedBoundaryTag := "boundary"
        },
        {
          slot := MinimalClaimSlot.restore
          verdict := RuntimeVerdict.evidenceMissing
          reason := "No signed restore-test attestation is present for the recovery corridor."
          solverBoundaryTag := "boundary"
          typedBoundaryTag := "boundary"
        }
      ] := by
  native_decide

end OpenCompliance.Controls.Typed
