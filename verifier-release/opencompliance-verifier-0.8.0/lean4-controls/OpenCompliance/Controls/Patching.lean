namespace OpenCompliance.Controls

structure SecurityUpdateEvidence where
  supportedVersionsOnly : Bool
  criticalOverdueCount : Nat
  patchWindowDays : Nat
deriving Repr, DecidableEq

def SupportedVersionsOnly (e : SecurityUpdateEvidence) : Prop :=
  e.supportedVersionsOnly = true

def NoCriticalUpdatesOverdue (e : SecurityUpdateEvidence) : Prop :=
  e.criticalOverdueCount = 0

def PatchWindowWithinFourteenDays (e : SecurityUpdateEvidence) : Prop :=
  e.patchWindowDays <= 14

def SupportedSecurityUpdatesCurrent (e : SecurityUpdateEvidence) : Prop :=
  SupportedVersionsOnly e ∧ NoCriticalUpdatesOverdue e ∧ PatchWindowWithinFourteenDays e

theorem supportedSecurityUpdatesCurrent_of_components
    (e : SecurityUpdateEvidence)
    (hsupported : e.supportedVersionsOnly = true)
    (hoverdue : e.criticalOverdueCount = 0)
    (hwindow : e.patchWindowDays <= 14) :
    SupportedSecurityUpdatesCurrent e := by
  exact And.intro hsupported (And.intro hoverdue hwindow)

end OpenCompliance.Controls
