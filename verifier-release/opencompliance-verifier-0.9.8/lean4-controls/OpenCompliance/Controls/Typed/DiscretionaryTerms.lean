import LegalLean.Core

namespace OpenCompliance.Controls.Typed

open LegalLean

axiom AppropriateTechnicalMeasures : Prop
axiom AdequateAccessControls : Prop
axiom ReasonableMonitoringCoverage : Prop
axiom OverallPolicySuiteAdequacy : Prop

instance vague_appropriateTechnicalMeasures : Vague AppropriateTechnicalMeasures where
  reason :=
    "GDPR Article 32 uses 'appropriate technical and organisational measures', " ++
    "which has no bright-line implementation threshold across systems and threat models."
  authority := Authority.accc
  core :=
    "Risk-ranked controls such as MFA, logging, encryption in transit, and least privilege " ++
    "are clearly within the settled core for internet-facing production systems."
  penumbra :=
    "Whether a particular control stack is appropriate for a specific processing context " ++
    "depends on residual risk, data sensitivity, attack surface, and current practice."

instance vague_adequateAccessControls : Vague AdequateAccessControls where
  reason :=
    "ISO 27001 and SOC 2 frequently require access controls to be 'adequate' " ++
    "for the environment, which depends on system criticality and threat assumptions."
  authority := Authority.accc
  core :=
    "Unique identities, MFA for admins, revocation on termination, and scoped role assignment."
  penumbra :=
    "Whether contractor access windows, emergency access procedures, or review cadence " ++
    "are adequate remains auditor- and context-sensitive."

instance vague_reasonableMonitoringCoverage : Vague ReasonableMonitoringCoverage where
  reason :=
    "SOC 2 monitoring expectations often reduce to whether the organisation provides " ++
    "'reasonable' coverage, but completeness and depth vary by risk and architecture."
  authority := Authority.accc
  core :=
    "Centralised audit logging, alerting on privileged events, and retention sufficient for investigation."
  penumbra :=
    "Whether a given alert set or retention horizon is reasonable for the business and risk profile " ++
    "requires professional judgment."

instance vague_overallPolicySuiteAdequacy : Vague OverallPolicySuiteAdequacy where
  reason :=
    "Whole-program policy adequacy is not reducible to a finite machine-readable threshold; " ++
    "it depends on scope, risk posture, and the interaction among technical, procedural, and legal controls."
  authority := Authority.accc
  core :=
    "A documented policy suite that covers the declared corridor, assigns ownership, and aligns with visible controls."
  penumbra :=
    "Whether the total policy set is adequate for the organisation and framework intent remains an auditor and management judgment."

def discretionaryBoundaryTerms : List (String × String × String) :=
  [
    ("GDPR Article 32", "appropriate technical measures", "Vague"),
    ("ISO 27001 / SOC 2", "adequate access controls", "Vague"),
    ("SOC 2", "reasonable monitoring coverage", "Vague"),
    ("ISO 27001 / SOC 2", "overall policy suite adequacy", "Vague")
  ]

def appropriateTechnicalMeasuresBoundary :
    FormalisationBoundary AppropriateTechnicalMeasures :=
  FormalisationBoundary.boundary
    vague_appropriateTechnicalMeasures.reason
    vague_appropriateTechnicalMeasures.authority

def adequateAccessControlsBoundary :
    FormalisationBoundary AdequateAccessControls :=
  FormalisationBoundary.boundary
    vague_adequateAccessControls.reason
    vague_adequateAccessControls.authority

def reasonableMonitoringCoverageBoundary :
    FormalisationBoundary ReasonableMonitoringCoverage :=
  FormalisationBoundary.boundary
    vague_reasonableMonitoringCoverage.reason
    vague_reasonableMonitoringCoverage.authority

def overallPolicySuiteAdequacyBoundary :
    FormalisationBoundary OverallPolicySuiteAdequacy :=
  FormalisationBoundary.boundary
    vague_overallPolicySuiteAdequacy.reason
    vague_overallPolicySuiteAdequacy.authority

theorem discretionaryBoundaryTerms_length :
    discretionaryBoundaryTerms.length = 4 := by
  decide

end OpenCompliance.Controls.Typed
