namespace OpenCompliance.Controls

structure EncryptionAtRestEvidence where
  encryptionEnabled : Bool
  customerDataStoresCovered : Bool
  unencryptedStoresPresent : Bool

def EncryptionAtRestEnabled (evidence : EncryptionAtRestEvidence) : Prop :=
  evidence.encryptionEnabled = true

def CustomerDataStoresCovered (evidence : EncryptionAtRestEvidence) : Prop :=
  evidence.customerDataStoresCovered = true

def NoUnencryptedCustomerDataStores (evidence : EncryptionAtRestEvidence) : Prop :=
  evidence.unencryptedStoresPresent = false

def EncryptionAtRestSatisfied (evidence : EncryptionAtRestEvidence) : Prop :=
  EncryptionAtRestEnabled evidence
    /\ CustomerDataStoresCovered evidence
    /\ NoUnencryptedCustomerDataStores evidence

theorem encryptionAtRestSatisfied_of_flags
    (evidence : EncryptionAtRestEvidence)
    (enc : evidence.encryptionEnabled = true)
    (covered : evidence.customerDataStoresCovered = true)
    (none_left : evidence.unencryptedStoresPresent = false) :
    EncryptionAtRestSatisfied evidence := by
  exact And.intro enc (And.intro covered none_left)

end OpenCompliance.Controls
