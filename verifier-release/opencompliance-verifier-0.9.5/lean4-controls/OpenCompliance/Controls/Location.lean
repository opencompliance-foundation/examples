namespace OpenCompliance.Controls

structure ApprovedRegionEvidence where
  approvedRegions : List String
  observedRegions : List String
  undeclaredRegionsPresent : Bool
deriving Repr, DecidableEq

def ApprovedRegionsDeclared (e : ApprovedRegionEvidence) : Prop :=
  e.approvedRegions ≠ []

def ObservedRegionsDeclared (e : ApprovedRegionEvidence) : Prop :=
  e.observedRegions ≠ []

def ObservedRegionsWithinApproved (e : ApprovedRegionEvidence) : Prop :=
  e.observedRegions.all (fun region => region ∈ e.approvedRegions) = true

def NoUndeclaredRegions (e : ApprovedRegionEvidence) : Prop :=
  e.undeclaredRegionsPresent = false

def ApprovedRegionBoundarySatisfied (e : ApprovedRegionEvidence) : Prop :=
  ApprovedRegionsDeclared e ∧ ObservedRegionsDeclared e ∧ ObservedRegionsWithinApproved e ∧ NoUndeclaredRegions e

theorem approvedRegionBoundarySatisfied_of_components
    (e : ApprovedRegionEvidence)
    (happroved : ApprovedRegionsDeclared e)
    (hobserved : ObservedRegionsDeclared e)
    (hsubset : ObservedRegionsWithinApproved e)
    (hclean : NoUndeclaredRegions e) :
    ApprovedRegionBoundarySatisfied e := by
  exact And.intro happroved (And.intro hobserved (And.intro hsubset hclean))

end OpenCompliance.Controls
