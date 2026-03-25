import LegalLean.Core
import OpenCompliance.Controls.Identity

namespace OpenCompliance.Controls.Typed

open LegalLean

/--
Typed extension of the narrow identity corridor.

`IdentityEvidence` stays unchanged and still drives the formalisable MFA predicate.
The additional training-attestation fields model the adjacent documentary slice
that must stay at the human-determination boundary.
-/
structure TypedIdentityEvidence where
  base : OpenCompliance.Controls.IdentityEvidence
  trainingAttestationExists : Bool
  trainingAttestationSigned : Bool
deriving Repr, DecidableEq

def TrainingAttestationPresent (e : TypedIdentityEvidence) : Prop :=
  e.trainingAttestationExists = true ∧ e.trainingAttestationSigned = true

instance decidableAdministrativeMfaSatisfied
    (e : OpenCompliance.Controls.IdentityEvidence) :
    Decidable (OpenCompliance.Controls.AdministrativeMfaSatisfied e) := by
  unfold OpenCompliance.Controls.AdministrativeMfaSatisfied
  infer_instance

instance decidableTrainingAttestationPresent
    (e : TypedIdentityEvidence) :
    Decidable (TrainingAttestationPresent e) := by
  unfold TrainingAttestationPresent
  infer_instance

/--
Whether the identity-training slice is sufficient for the corridor cannot be
machine discharged from the documentary record alone. The attestation is real;
its adequacy still requires a human determination.
-/
axiom TrainingAttestationSatisfiesIdentityControl : TypedIdentityEvidence → Prop

instance trainingAttestationRequiresHumanDetermination
    (e : TypedIdentityEvidence) :
    RequiresHumanDetermination (TrainingAttestationSatisfiesIdentityControl e) where
  reason :=
    "Training completion for the identity corridor is documentary evidence only; " ++
    "a reviewer must determine whether the attestation is current, in scope, and " ++
    "sufficient for the affected administrative population."
  authority := Authority.accc

/--
Temporary proxy authority note:
`Authority.accc` is re-used here as a stand-in for the external certification
or assurance body until LegalLean exposes a compliance-specific authority enum.
-/
def certificationBodyProxy : Authority :=
  Authority.accc

def typedAdministrativeMfaResult
    (e : OpenCompliance.Controls.IdentityEvidence) :
    FormalisationBoundary (OpenCompliance.Controls.AdministrativeMfaSatisfied e) :=
  if h : OpenCompliance.Controls.AdministrativeMfaSatisfied e then
    FormalisationBoundary.formal h
  else
    FormalisationBoundary.boundary
      "Administrative MFA is not fully configured in the scoped production environment."
      certificationBodyProxy

def typedTrainingAttestationResult
    (e : TypedIdentityEvidence) :
    FormalisationBoundary (TrainingAttestationSatisfiesIdentityControl e) :=
  if TrainingAttestationPresent e then
    let inst :=
      trainingAttestationRequiresHumanDetermination e
    FormalisationBoundary.boundary inst.reason inst.authority
  else
    FormalisationBoundary.boundary
      "No signed training attestation is present for the identity corridor."
      certificationBodyProxy

def typedIdentityResults
    (e : TypedIdentityEvidence) :
    FormalisationBoundary (OpenCompliance.Controls.AdministrativeMfaSatisfied e.base) ×
      FormalisationBoundary (TrainingAttestationSatisfiesIdentityControl e) :=
  (typedAdministrativeMfaResult e.base, typedTrainingAttestationResult e)

theorem typedAdministrativeMfaResult_of_flags
    (e : OpenCompliance.Controls.IdentityEvidence)
    (hmfa : e.mfaRequired = true)
    (hca : e.conditionalAccessEnabled = true) :
    typedAdministrativeMfaResult e =
      FormalisationBoundary.formal
        (OpenCompliance.Controls.administrativeMfaSatisfied_of_flags e hmfa hca) := by
  let hs :=
    OpenCompliance.Controls.administrativeMfaSatisfied_of_flags e hmfa hca
  unfold typedAdministrativeMfaResult
  simp [hs]

theorem typedTrainingAttestationResult_is_boundary
    (e : TypedIdentityEvidence) :
    ∃ reason authority,
      typedTrainingAttestationResult e =
        FormalisationBoundary.boundary reason authority := by
  by_cases h : TrainingAttestationPresent e
  · refine ⟨(trainingAttestationRequiresHumanDetermination e).reason,
      (trainingAttestationRequiresHumanDetermination e).authority, ?_⟩
    simp [typedTrainingAttestationResult, h, trainingAttestationRequiresHumanDetermination]
  · refine ⟨"No signed training attestation is present for the identity corridor.",
      certificationBodyProxy, ?_⟩
    simp [typedTrainingAttestationResult, h, certificationBodyProxy]

end OpenCompliance.Controls.Typed
