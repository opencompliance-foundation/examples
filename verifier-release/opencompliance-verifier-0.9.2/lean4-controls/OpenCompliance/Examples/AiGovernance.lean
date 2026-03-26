import OpenCompliance.Controls.AI

namespace OpenCompliance.Examples

def aiGovernanceContentLabelingEvidence : OpenCompliance.Controls.AiContentLabelingEvidence := {
  labelingEnabled := true
  metadataMarkerEnabled := true
  enforcementChecksPassing := true
}

theorem exClaim705_proved :
    OpenCompliance.Controls.AiGeneratedContentDisclosureConfigured aiGovernanceContentLabelingEvidence := by
  exact OpenCompliance.Controls.aiGeneratedContentDisclosureConfigured_of_flags
    aiGovernanceContentLabelingEvidence rfl rfl rfl

end OpenCompliance.Examples
