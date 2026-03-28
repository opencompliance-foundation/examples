namespace OpenCompliance.Controls

structure MalwareProtectionEvidence where
  protectionEnabled : Bool
  signaturesCurrent : Bool
  tamperProtectionEnabled : Bool
deriving Repr, DecidableEq

def MalwareProtectionEnabled (e : MalwareProtectionEvidence) : Prop :=
  e.protectionEnabled = true

def MalwareSignaturesCurrent (e : MalwareProtectionEvidence) : Prop :=
  e.signaturesCurrent = true

def TamperProtectionEnabled (e : MalwareProtectionEvidence) : Prop :=
  e.tamperProtectionEnabled = true

def MalwareProtectionBaselineSatisfied (e : MalwareProtectionEvidence) : Prop :=
  MalwareProtectionEnabled e ∧ MalwareSignaturesCurrent e ∧ TamperProtectionEnabled e

theorem malwareProtectionBaselineSatisfied_of_flags
    (e : MalwareProtectionEvidence)
    (hprotected : e.protectionEnabled = true)
    (hsignatures : e.signaturesCurrent = true)
    (htamper : e.tamperProtectionEnabled = true) :
    MalwareProtectionBaselineSatisfied e := by
  exact And.intro hprotected (And.intro hsignatures htamper)

end OpenCompliance.Controls
