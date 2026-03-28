namespace OpenCompliance.Controls

structure TlsIngressEvidence where
  httpsOnly : Bool
  minTlsVersion12OrHigher : Bool
  managedCertificatesActive : Bool
  plaintextDisabled : Bool
deriving Repr, DecidableEq

def HttpsOnly (e : TlsIngressEvidence) : Prop :=
  e.httpsOnly = true

def TlsVersionAtLeast12 (e : TlsIngressEvidence) : Prop :=
  e.minTlsVersion12OrHigher = true

def ManagedCertificatesActive (e : TlsIngressEvidence) : Prop :=
  e.managedCertificatesActive = true

def TlsIngressSatisfied (e : TlsIngressEvidence) : Prop :=
  HttpsOnly e ∧ TlsVersionAtLeast12 e ∧ ManagedCertificatesActive e

def PlaintextTransportDisabled (e : TlsIngressEvidence) : Prop :=
  HttpsOnly e ∧ e.plaintextDisabled = true

theorem tlsIngressSatisfied_of_flags
    (e : TlsIngressEvidence)
    (hhttps : e.httpsOnly = true)
    (htls : e.minTlsVersion12OrHigher = true)
    (hcerts : e.managedCertificatesActive = true) :
    TlsIngressSatisfied e := by
  exact And.intro hhttps (And.intro htls hcerts)

theorem plaintextTransportDisabled_of_flags
    (e : TlsIngressEvidence)
    (hhttps : e.httpsOnly = true)
    (hplaintext : e.plaintextDisabled = true) :
    PlaintextTransportDisabled e := by
  exact And.intro hhttps hplaintext

structure WebApplicationFirewallEvidence where
  wafAttachedToPublicIngress : Bool
  blockingModeEnabled : Bool
  managedRuleSetActive : Bool
deriving Repr, DecidableEq

def WafAttachedToPublicIngress (e : WebApplicationFirewallEvidence) : Prop :=
  e.wafAttachedToPublicIngress = true

def WafBlockingModeEnabled (e : WebApplicationFirewallEvidence) : Prop :=
  e.blockingModeEnabled = true

def ManagedWafRuleSetActive (e : WebApplicationFirewallEvidence) : Prop :=
  e.managedRuleSetActive = true

def WebApplicationFirewallSatisfied (e : WebApplicationFirewallEvidence) : Prop :=
  WafAttachedToPublicIngress e ∧ WafBlockingModeEnabled e ∧ ManagedWafRuleSetActive e

theorem webApplicationFirewallSatisfied_of_flags
    (e : WebApplicationFirewallEvidence)
    (hattached : e.wafAttachedToPublicIngress = true)
    (hblocking : e.blockingModeEnabled = true)
    (hrules : e.managedRuleSetActive = true) :
    WebApplicationFirewallSatisfied e := by
  exact And.intro hattached (And.intro hblocking hrules)

structure NetworkBoundaryEvidence where
  defaultDenyInbound : Bool
  declaredIngressPortsPresent : Bool
  undeclaredIngressPresent : Bool
  boundaryAttachedToIngressPath : Bool
  adminIngressRestricted : Bool
  approvedAdminSourceRangesDeclared : Bool
  unapprovedAdminIngressPresent : Bool
deriving Repr, DecidableEq

def DefaultDenyInbound (e : NetworkBoundaryEvidence) : Prop :=
  e.defaultDenyInbound = true

def DeclaredIngressPortsPresent (e : NetworkBoundaryEvidence) : Prop :=
  e.declaredIngressPortsPresent = true

def NoUndeclaredIngressPresent (e : NetworkBoundaryEvidence) : Prop :=
  e.undeclaredIngressPresent = false

def DefaultDenyNetworkBoundarySatisfied (e : NetworkBoundaryEvidence) : Prop :=
  DefaultDenyInbound e ∧ DeclaredIngressPortsPresent e ∧ NoUndeclaredIngressPresent e

def BoundaryAttachedToIngressPath (e : NetworkBoundaryEvidence) : Prop :=
  e.boundaryAttachedToIngressPath = true

def ManagedIngressBoundaryAttached (e : NetworkBoundaryEvidence) : Prop :=
  DefaultDenyNetworkBoundarySatisfied e ∧ BoundaryAttachedToIngressPath e

def AdminIngressRestricted (e : NetworkBoundaryEvidence) : Prop :=
  e.adminIngressRestricted = true

def ApprovedAdminSourceRangesDeclared (e : NetworkBoundaryEvidence) : Prop :=
  e.approvedAdminSourceRangesDeclared = true

def NoUnapprovedAdminIngressPresent (e : NetworkBoundaryEvidence) : Prop :=
  e.unapprovedAdminIngressPresent = false

def AdministrativeIngressRestricted (e : NetworkBoundaryEvidence) : Prop :=
  DefaultDenyNetworkBoundarySatisfied e ∧ AdminIngressRestricted e ∧
    ApprovedAdminSourceRangesDeclared e ∧ NoUnapprovedAdminIngressPresent e

theorem defaultDenyNetworkBoundarySatisfied_of_flags
    (e : NetworkBoundaryEvidence)
    (hdeny : e.defaultDenyInbound = true)
    (hports : e.declaredIngressPortsPresent = true)
    (hundeclared : e.undeclaredIngressPresent = false) :
    DefaultDenyNetworkBoundarySatisfied e := by
  exact And.intro hdeny (And.intro hports hundeclared)

theorem managedIngressBoundaryAttached_of_flags
    (e : NetworkBoundaryEvidence)
    (hdeny : e.defaultDenyInbound = true)
    (hports : e.declaredIngressPortsPresent = true)
    (hundeclared : e.undeclaredIngressPresent = false)
    (hattached : e.boundaryAttachedToIngressPath = true) :
    ManagedIngressBoundaryAttached e := by
  exact And.intro
    (defaultDenyNetworkBoundarySatisfied_of_flags e hdeny hports hundeclared)
    hattached

theorem administrativeIngressRestricted_of_flags
    (e : NetworkBoundaryEvidence)
    (hdeny : e.defaultDenyInbound = true)
    (hports : e.declaredIngressPortsPresent = true)
    (hundeclared : e.undeclaredIngressPresent = false)
    (hrestricted : e.adminIngressRestricted = true)
    (hranges : e.approvedAdminSourceRangesDeclared = true)
    (hunapproved : e.unapprovedAdminIngressPresent = false) :
    AdministrativeIngressRestricted e := by
  exact And.intro
    (defaultDenyNetworkBoundarySatisfied_of_flags e hdeny hports hundeclared)
    (And.intro hrestricted (And.intro hranges hunapproved))

structure RemoteAccessPostureEvidence where
  remotePathDeclared : Bool
  devicePostureBounded : Bool
  systemCount : Nat
deriving Repr, DecidableEq

def RemotePathDeclared (e : RemoteAccessPostureEvidence) : Prop :=
  e.remotePathDeclared = true

def DevicePostureBounded (e : RemoteAccessPostureEvidence) : Prop :=
  e.devicePostureBounded = true

def ScopedRemoteSystemsDeclared (e : RemoteAccessPostureEvidence) : Prop :=
  0 < e.systemCount

def RemoteAccessPostureDeclared (e : RemoteAccessPostureEvidence) : Prop :=
  RemotePathDeclared e ∧ DevicePostureBounded e ∧ ScopedRemoteSystemsDeclared e

theorem remoteAccessPostureDeclared_of_components
    (e : RemoteAccessPostureEvidence)
    (hpath : e.remotePathDeclared = true)
    (hdevice : e.devicePostureBounded = true)
    (hsystems : 0 < e.systemCount) :
    RemoteAccessPostureDeclared e := by
  exact And.intro hpath (And.intro hdevice hsystems)

structure EnvironmentSegmentationEvidence where
  customerBoundaryEnforced : Bool
  productionSeparatedFromNonProduction : Bool
  undeclaredCrossEnvironmentPathsPresent : Bool
deriving Repr, DecidableEq

def CustomerBoundaryEnforced (e : EnvironmentSegmentationEvidence) : Prop :=
  e.customerBoundaryEnforced = true

def ProductionSeparatedFromNonProduction (e : EnvironmentSegmentationEvidence) : Prop :=
  e.productionSeparatedFromNonProduction = true

def NoUndeclaredCrossEnvironmentPathsPresent (e : EnvironmentSegmentationEvidence) : Prop :=
  e.undeclaredCrossEnvironmentPathsPresent = false

def EnvironmentSegmentationSatisfied (e : EnvironmentSegmentationEvidence) : Prop :=
  CustomerBoundaryEnforced e ∧
    ProductionSeparatedFromNonProduction e ∧
    NoUndeclaredCrossEnvironmentPathsPresent e

theorem environmentSegmentationSatisfied_of_flags
    (e : EnvironmentSegmentationEvidence)
    (hcustomer : e.customerBoundaryEnforced = true)
    (hproduction : e.productionSeparatedFromNonProduction = true)
    (hpaths : e.undeclaredCrossEnvironmentPathsPresent = false) :
    EnvironmentSegmentationSatisfied e := by
  exact And.intro hcustomer (And.intro hproduction hpaths)

end OpenCompliance.Controls
