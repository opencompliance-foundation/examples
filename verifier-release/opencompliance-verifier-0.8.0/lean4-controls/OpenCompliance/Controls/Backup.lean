namespace OpenCompliance.Controls

structure BackupSnapshotEvidence where
  snapshotsEnabled : Bool
  snapshotFrequencyHours : Nat
  immutableWindowDays : Nat
deriving Repr, DecidableEq

def SnapshotsEnabled (e : BackupSnapshotEvidence) : Prop :=
  e.snapshotsEnabled = true

def SnapshotFrequencyDeclared (e : BackupSnapshotEvidence) : Prop :=
  0 < e.snapshotFrequencyHours

def ImmutableWindowDeclared (e : BackupSnapshotEvidence) : Prop :=
  0 < e.immutableWindowDays

def BackupSnapshotScheduleSatisfied (e : BackupSnapshotEvidence) : Prop :=
  SnapshotsEnabled e ∧ SnapshotFrequencyDeclared e ∧ ImmutableWindowDeclared e

theorem backupSnapshotScheduleSatisfied_of_components
    (e : BackupSnapshotEvidence)
    (henabled : SnapshotsEnabled e)
    (hfrequency : SnapshotFrequencyDeclared e)
    (hwindow : ImmutableWindowDeclared e) :
    BackupSnapshotScheduleSatisfied e := by
  exact And.intro henabled (And.intro hfrequency hwindow)

end OpenCompliance.Controls
