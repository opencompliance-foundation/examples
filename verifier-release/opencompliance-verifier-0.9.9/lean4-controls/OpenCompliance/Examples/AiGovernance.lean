import OpenCompliance.Controls.AI

namespace OpenCompliance.Examples

def aiGovernanceContentLabelingEvidence : OpenCompliance.Controls.AiContentLabelingEvidence := {
  labelingEnabled := true
  metadataMarkerEnabled := true
  enforcementChecksPassing := true
}

def aiGovernanceContentProvenanceEvidence : OpenCompliance.Controls.AiContentProvenanceEvidence := {
  provenanceMetadataEnabled := true
  originHistoryRetained := true
  verificationChecksPassing := true
}

def aiGovernanceTaskEnvelopeEvidence : OpenCompliance.Controls.AiTaskEnvelopeEvidence := {
  purposeDeclared := true
  allowedToolClassesDeclared := true
  allowedDataClassesDeclared := true
  retentionClassDeclared := true
  humanReviewLinkagePresent := true
}

def aiGovernanceRightsReadyRunTraceEvidence : OpenCompliance.Controls.AiRightsReadyRunTraceEvidence := {
  traceRetentionEnabled := true
  requestPurposeCaptured := true
  inputClassificationsCaptured := true
  outputReferencesCaptured := true
  humanReviewLinkagePresent := true
}

def aiGovernancePrivacyNoticePublicationEvidence : OpenCompliance.Controls.PrivacyNoticePublicationEvidence := {
  noticePublished := true
  categoriesAndPurposesListed := true
  rightsProcessLinked := true
  noticeUrlReachable := true
  reviewWindowDays := 30
}

theorem exClaim705_proved :
    OpenCompliance.Controls.AiGeneratedContentDisclosureConfigured aiGovernanceContentLabelingEvidence := by
  exact OpenCompliance.Controls.aiGeneratedContentDisclosureConfigured_of_flags
    aiGovernanceContentLabelingEvidence rfl rfl rfl

theorem exClaim706_proved :
    OpenCompliance.Controls.AiContentProvenanceConfigured aiGovernanceContentProvenanceEvidence := by
  exact OpenCompliance.Controls.aiContentProvenanceConfigured_of_flags
    aiGovernanceContentProvenanceEvidence rfl rfl rfl

theorem exClaim713_proved :
    OpenCompliance.Controls.AiTaskEnvelopeBounded aiGovernanceTaskEnvelopeEvidence := by
  exact OpenCompliance.Controls.aiTaskEnvelopeBounded_of_flags
    aiGovernanceTaskEnvelopeEvidence rfl rfl rfl rfl rfl

theorem exClaim714_proved :
    OpenCompliance.Controls.AiRightsReadyRunTraceRetained aiGovernanceRightsReadyRunTraceEvidence := by
  exact OpenCompliance.Controls.aiRightsReadyRunTraceRetained_of_flags
    aiGovernanceRightsReadyRunTraceEvidence rfl rfl rfl rfl rfl

theorem exClaim716_proved :
    OpenCompliance.Controls.PrivacyNoticePublicationStateCaptured aiGovernancePrivacyNoticePublicationEvidence := by
  exact OpenCompliance.Controls.privacyNoticePublicationStateCaptured_of_components
    aiGovernancePrivacyNoticePublicationEvidence rfl rfl rfl rfl (by decide)

end OpenCompliance.Examples
