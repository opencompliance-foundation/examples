namespace OpenCompliance.Controls

structure ServiceAccountKeyEvidence where
  userManagedKeysPresent : Bool
  maxUserManagedKeyAgeDays : Nat
deriving Repr, DecidableEq

def NoUserManagedServiceAccountKeys (e : ServiceAccountKeyEvidence) : Prop :=
  e.userManagedKeysPresent = false

def NoLongLivedUserManagedKeys (e : ServiceAccountKeyEvidence) : Prop :=
  e.maxUserManagedKeyAgeDays = 0

def NarrowServiceAccountKeyCorridor (e : ServiceAccountKeyEvidence) : Prop :=
  NoUserManagedServiceAccountKeys e ∧ NoLongLivedUserManagedKeys e

theorem narrowServiceAccountKeyCorridor_of_flags
    (e : ServiceAccountKeyEvidence)
    (hpresent : e.userManagedKeysPresent = false)
    (hage : e.maxUserManagedKeyAgeDays = 0) :
    NarrowServiceAccountKeyCorridor e := by
  exact And.intro hpresent hage

end OpenCompliance.Controls
