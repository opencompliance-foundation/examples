import Lean
import LegalLean.Core

open Lean

namespace OpenCompliance.Controls.Typed

inductive PublicRuntimeVerdict where
  | proved
  | attested
  | failed
  | staleEvidence
  | judgmentRequired
  | evidenceMissing
  deriving Repr, BEq, DecidableEq

structure PublicRuntimeClaimDecision where
  claimId : String
  slot : String
  verdict : PublicRuntimeVerdict
  reason : String
  solverBoundaryTag : String
  typedBoundaryTag : String
  deriving Repr, DecidableEq

def publicRuntimeVerdictLabel : PublicRuntimeVerdict → String
  | .proved => "proved"
  | .attested => "attested"
  | .failed => "failed"
  | .staleEvidence => "stale_evidence"
  | .judgmentRequired => "judgment_required"
  | .evidenceMissing => "evidence_missing"

instance : ToJson PublicRuntimeVerdict where
  toJson verdict := toJson (publicRuntimeVerdictLabel verdict)

instance : ToJson PublicRuntimeClaimDecision where
  toJson decision :=
    Json.mkObj
      [("claimId", toJson decision.claimId),
       ("slot", toJson decision.slot),
       ("verdict", toJson decision.verdict),
       ("reason", toJson decision.reason),
       ("solverBoundaryTag", toJson decision.solverBoundaryTag),
       ("typedBoundaryTag", toJson decision.typedBoundaryTag)]

private def mkDecision
    (claimId slot : String)
    (verdict : PublicRuntimeVerdict)
    (reason solverBoundaryTag typedBoundaryTag : String) :
    PublicRuntimeClaimDecision := {
      claimId := claimId
      slot := slot
      verdict := verdict
      reason := reason
      solverBoundaryTag := solverBoundaryTag
      typedBoundaryTag := typedBoundaryTag
    }

def formalDecision
    (claimId slot : String)
    (evidencePresent evidenceFresh satisfied : Bool) :
    PublicRuntimeClaimDecision :=
  if evidencePresent = false then
    mkDecision claimId slot .evidenceMissing
      "No typed evidence claim is attached for this formal corridor slot."
      "formal_evidence_missing"
      "FormalisationBoundary.boundary"
  else if evidenceFresh = false then
    mkDecision claimId slot .staleEvidence
      "Typed evidence exists for this formal corridor slot, but freshness has expired."
      "formal_freshness_boundary"
      "FormalisationBoundary.boundary"
  else if satisfied then
    mkDecision claimId slot .proved
      "The scoped formal predicate is satisfied by the attached evidence."
      "formal_predicate_satisfied"
      "FormalisationBoundary.formal"
  else
    mkDecision claimId slot .failed
      "Typed evidence is present, but the scoped formal predicate is false."
      "formal_predicate_failed"
      "FormalisationBoundary.formal"

def documentaryDecision
    (claimId slot : String)
    (evidencePresent evidenceFresh satisfied : Bool) :
    PublicRuntimeClaimDecision :=
  if evidencePresent = false then
    mkDecision claimId slot .evidenceMissing
      "No typed documentary attestation is attached for this boundary slot."
      "documentary_evidence_missing"
      "FormalisationBoundary.boundary"
  else if evidenceFresh = false then
    mkDecision claimId slot .staleEvidence
      "Typed documentary evidence exists for this boundary slot, but freshness has expired."
      "documentary_freshness_boundary"
      "FormalisationBoundary.boundary"
  else if satisfied then
    mkDecision claimId slot .attested
      "The documentary attestation requirements are satisfied for the attached evidence."
      "documentary_attestation_satisfied"
      "FormalisationBoundary.boundary"
  else
    mkDecision claimId slot .failed
      "Typed documentary evidence is present, but the attestation predicate is false."
      "documentary_attestation_failed"
      "FormalisationBoundary.boundary"

def judgmentDecision (claimId slot : String) : PublicRuntimeClaimDecision :=
  mkDecision claimId slot .judgmentRequired
    "This slot remains explicitly dependent on human adequacy or interpretation."
    "human_determination_required"
    "RequiresHumanDetermination"

end OpenCompliance.Controls.Typed
