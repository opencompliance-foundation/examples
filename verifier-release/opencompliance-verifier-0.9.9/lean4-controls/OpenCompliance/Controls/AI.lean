namespace OpenCompliance.Controls

structure AiContentLabelingEvidence where
  labelingEnabled : Bool
  metadataMarkerEnabled : Bool
  enforcementChecksPassing : Bool
deriving Repr, DecidableEq

structure AiContentProvenanceEvidence where
  provenanceMetadataEnabled : Bool
  originHistoryRetained : Bool
  verificationChecksPassing : Bool
deriving Repr, DecidableEq

structure AiTaskEnvelopeEvidence where
  purposeDeclared : Bool
  allowedToolClassesDeclared : Bool
  allowedDataClassesDeclared : Bool
  retentionClassDeclared : Bool
  humanReviewLinkagePresent : Bool
deriving Repr, DecidableEq

structure AiRightsReadyRunTraceEvidence where
  traceRetentionEnabled : Bool
  requestPurposeCaptured : Bool
  inputClassificationsCaptured : Bool
  outputReferencesCaptured : Bool
  humanReviewLinkagePresent : Bool
deriving Repr, DecidableEq

structure PrivacyNoticePublicationEvidence where
  noticePublished : Bool
  categoriesAndPurposesListed : Bool
  rightsProcessLinked : Bool
  noticeUrlReachable : Bool
  reviewWindowDays : Nat
deriving Repr, DecidableEq

def ContentLabelingEnabled (e : AiContentLabelingEvidence) : Prop :=
  e.labelingEnabled = true

def MetadataMarkerEnabled (e : AiContentLabelingEvidence) : Prop :=
  e.metadataMarkerEnabled = true

def DisclosureEnforcementChecksPassing (e : AiContentLabelingEvidence) : Prop :=
  e.enforcementChecksPassing = true

def AiGeneratedContentDisclosureConfigured (e : AiContentLabelingEvidence) : Prop :=
  ContentLabelingEnabled e ∧ MetadataMarkerEnabled e ∧ DisclosureEnforcementChecksPassing e

theorem aiGeneratedContentDisclosureConfigured_of_flags
    (e : AiContentLabelingEvidence)
    (hlabeling : e.labelingEnabled = true)
    (hmetadata : e.metadataMarkerEnabled = true)
    (henforcement : e.enforcementChecksPassing = true) :
    AiGeneratedContentDisclosureConfigured e := by
  exact And.intro hlabeling (And.intro hmetadata henforcement)

def ProvenanceMetadataEnabled (e : AiContentProvenanceEvidence) : Prop :=
  e.provenanceMetadataEnabled = true

def OriginHistoryRetained (e : AiContentProvenanceEvidence) : Prop :=
  e.originHistoryRetained = true

def ProvenanceVerificationChecksPassing (e : AiContentProvenanceEvidence) : Prop :=
  e.verificationChecksPassing = true

def AiContentProvenanceConfigured (e : AiContentProvenanceEvidence) : Prop :=
  ProvenanceMetadataEnabled e ∧ OriginHistoryRetained e ∧ ProvenanceVerificationChecksPassing e

theorem aiContentProvenanceConfigured_of_flags
    (e : AiContentProvenanceEvidence)
    (hmetadata : e.provenanceMetadataEnabled = true)
    (horigin : e.originHistoryRetained = true)
    (hverification : e.verificationChecksPassing = true) :
    AiContentProvenanceConfigured e := by
  exact And.intro hmetadata (And.intro horigin hverification)

def PurposeDeclared (e : AiTaskEnvelopeEvidence) : Prop :=
  e.purposeDeclared = true

def AllowedToolClassesDeclared (e : AiTaskEnvelopeEvidence) : Prop :=
  e.allowedToolClassesDeclared = true

def AllowedDataClassesDeclared (e : AiTaskEnvelopeEvidence) : Prop :=
  e.allowedDataClassesDeclared = true

def RetentionClassDeclared (e : AiTaskEnvelopeEvidence) : Prop :=
  e.retentionClassDeclared = true

def TaskEnvelopeHumanReviewLinked (e : AiTaskEnvelopeEvidence) : Prop :=
  e.humanReviewLinkagePresent = true

def AiTaskEnvelopeBounded (e : AiTaskEnvelopeEvidence) : Prop :=
  PurposeDeclared e ∧
  AllowedToolClassesDeclared e ∧
  AllowedDataClassesDeclared e ∧
  RetentionClassDeclared e ∧
  TaskEnvelopeHumanReviewLinked e

theorem aiTaskEnvelopeBounded_of_flags
    (e : AiTaskEnvelopeEvidence)
    (hpurpose : e.purposeDeclared = true)
    (htools : e.allowedToolClassesDeclared = true)
    (hdata : e.allowedDataClassesDeclared = true)
    (hretention : e.retentionClassDeclared = true)
    (hreview : e.humanReviewLinkagePresent = true) :
    AiTaskEnvelopeBounded e := by
  exact And.intro hpurpose (And.intro htools (And.intro hdata (And.intro hretention hreview)))

def TraceRetentionEnabled (e : AiRightsReadyRunTraceEvidence) : Prop :=
  e.traceRetentionEnabled = true

def RequestPurposeCaptured (e : AiRightsReadyRunTraceEvidence) : Prop :=
  e.requestPurposeCaptured = true

def InputClassificationsCaptured (e : AiRightsReadyRunTraceEvidence) : Prop :=
  e.inputClassificationsCaptured = true

def OutputReferencesCaptured (e : AiRightsReadyRunTraceEvidence) : Prop :=
  e.outputReferencesCaptured = true

def RunTraceHumanReviewLinked (e : AiRightsReadyRunTraceEvidence) : Prop :=
  e.humanReviewLinkagePresent = true

def AiRightsReadyRunTraceRetained (e : AiRightsReadyRunTraceEvidence) : Prop :=
  TraceRetentionEnabled e ∧
  RequestPurposeCaptured e ∧
  InputClassificationsCaptured e ∧
  OutputReferencesCaptured e ∧
  RunTraceHumanReviewLinked e

theorem aiRightsReadyRunTraceRetained_of_flags
    (e : AiRightsReadyRunTraceEvidence)
    (hretention : e.traceRetentionEnabled = true)
    (hpurpose : e.requestPurposeCaptured = true)
    (hinput : e.inputClassificationsCaptured = true)
    (houtput : e.outputReferencesCaptured = true)
    (hreview : e.humanReviewLinkagePresent = true) :
    AiRightsReadyRunTraceRetained e := by
  exact And.intro hretention (And.intro hpurpose (And.intro hinput (And.intro houtput hreview)))

def PrivacyNoticePublished (e : PrivacyNoticePublicationEvidence) : Prop :=
  e.noticePublished = true

def CategoriesAndPurposesListed (e : PrivacyNoticePublicationEvidence) : Prop :=
  e.categoriesAndPurposesListed = true

def RightsProcessLinked (e : PrivacyNoticePublicationEvidence) : Prop :=
  e.rightsProcessLinked = true

def NoticeUrlReachable (e : PrivacyNoticePublicationEvidence) : Prop :=
  e.noticeUrlReachable = true

def NoticeReviewWindowDeclared (e : PrivacyNoticePublicationEvidence) : Prop :=
  e.reviewWindowDays > 0

def PrivacyNoticePublicationStateCaptured (e : PrivacyNoticePublicationEvidence) : Prop :=
  PrivacyNoticePublished e ∧
  CategoriesAndPurposesListed e ∧
  RightsProcessLinked e ∧
  NoticeUrlReachable e ∧
  NoticeReviewWindowDeclared e

theorem privacyNoticePublicationStateCaptured_of_components
    (e : PrivacyNoticePublicationEvidence)
    (hpublished : e.noticePublished = true)
    (hcategories : e.categoriesAndPurposesListed = true)
    (hrights : e.rightsProcessLinked = true)
    (hreachable : e.noticeUrlReachable = true)
    (hwindow : e.reviewWindowDays > 0) :
    PrivacyNoticePublicationStateCaptured e := by
  exact And.intro hpublished (And.intro hcategories (And.intro hrights (And.intro hreachable hwindow)))

end OpenCompliance.Controls
