namespace OpenCompliance.Controls

structure SecureConfigurationEvidence where
  baselineApplied : Bool
  insecureDefaultsPresent : Bool
  snapshotAgeDays : Nat
deriving Repr, DecidableEq

def BaselineApplied (e : SecureConfigurationEvidence) : Prop :=
  e.baselineApplied = true

def NoInsecureDefaultsPresent (e : SecureConfigurationEvidence) : Prop :=
  e.insecureDefaultsPresent = false

def SnapshotFreshWithinThirtyDays (e : SecureConfigurationEvidence) : Prop :=
  e.snapshotAgeDays <= 30

def SecureConfigurationBaselineSatisfied (e : SecureConfigurationEvidence) : Prop :=
  BaselineApplied e ∧ NoInsecureDefaultsPresent e ∧ SnapshotFreshWithinThirtyDays e

theorem secureConfigurationBaselineSatisfied_of_components
    (e : SecureConfigurationEvidence)
    (hbaseline : e.baselineApplied = true)
    (hdefaults : e.insecureDefaultsPresent = false)
    (hage : e.snapshotAgeDays <= 30) :
    SecureConfigurationBaselineSatisfied e := by
  exact And.intro hbaseline (And.intro hdefaults hage)

end OpenCompliance.Controls
