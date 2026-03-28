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

theorem exClaim705_proved :
    OpenCompliance.Controls.AiGeneratedContentDisclosureConfigured aiGovernanceContentLabelingEvidence := by
  exact OpenCompliance.Controls.aiGeneratedContentDisclosureConfigured_of_flags
    aiGovernanceContentLabelingEvidence rfl rfl rfl

theorem exClaim706_proved :
    OpenCompliance.Controls.AiContentProvenanceConfigured aiGovernanceContentProvenanceEvidence := by
  exact OpenCompliance.Controls.aiContentProvenanceConfigured_of_flags
    aiGovernanceContentProvenanceEvidence rfl rfl rfl

end OpenCompliance.Examples
