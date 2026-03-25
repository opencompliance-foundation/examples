namespace OpenCompliance.Controls

structure RepoBranchProtectionEvidence where
  defaultBranchProtected : Bool
  requiredApprovals : Nat
  statusChecksRequired : Bool
  forcePushesBlocked : Bool
  adminBypassRestricted : Bool
deriving Repr, DecidableEq

structure CiWorkflowPolicyEvidence where
  workflowReviewRequired : Bool
  trustedPublishingOnly : Bool
  protectedRefsOnly : Bool
  environmentApprovalsRequired : Bool
deriving Repr, DecidableEq

def DefaultBranchProtected (e : RepoBranchProtectionEvidence) : Prop :=
  e.defaultBranchProtected = true

def RequiredApprovalsDeclared (e : RepoBranchProtectionEvidence) : Prop :=
  0 < e.requiredApprovals

def StatusChecksRequired (e : RepoBranchProtectionEvidence) : Prop :=
  e.statusChecksRequired = true

def ForcePushesBlocked (e : RepoBranchProtectionEvidence) : Prop :=
  e.forcePushesBlocked = true

def AdminBypassRestricted (e : RepoBranchProtectionEvidence) : Prop :=
  e.adminBypassRestricted = true

def DefaultBranchProtectionsEnforced (e : RepoBranchProtectionEvidence) : Prop :=
  DefaultBranchProtected e ∧ RequiredApprovalsDeclared e ∧
    StatusChecksRequired e ∧ ForcePushesBlocked e ∧ AdminBypassRestricted e

def WorkflowReviewRequired (e : CiWorkflowPolicyEvidence) : Prop :=
  e.workflowReviewRequired = true

def TrustedPublishingOnly (e : CiWorkflowPolicyEvidence) : Prop :=
  e.trustedPublishingOnly = true

def ProtectedRefsOnly (e : CiWorkflowPolicyEvidence) : Prop :=
  e.protectedRefsOnly = true

def EnvironmentApprovalsRequired (e : CiWorkflowPolicyEvidence) : Prop :=
  e.environmentApprovalsRequired = true

def CiWorkflowPolicyConstrained (e : CiWorkflowPolicyEvidence) : Prop :=
  WorkflowReviewRequired e ∧ TrustedPublishingOnly e ∧
    ProtectedRefsOnly e ∧ EnvironmentApprovalsRequired e

theorem defaultBranchProtectionsEnforced_of_components
    (e : RepoBranchProtectionEvidence)
    (hprotected : e.defaultBranchProtected = true)
    (happrovals : 0 < e.requiredApprovals)
    (hchecks : e.statusChecksRequired = true)
    (hforce : e.forcePushesBlocked = true)
    (hbypass : e.adminBypassRestricted = true) :
    DefaultBranchProtectionsEnforced e := by
  exact And.intro hprotected
    (And.intro happrovals
      (And.intro hchecks
        (And.intro hforce hbypass)))

theorem ciWorkflowPolicyConstrained_of_flags
    (e : CiWorkflowPolicyEvidence)
    (hreview : e.workflowReviewRequired = true)
    (htrusted : e.trustedPublishingOnly = true)
    (hrefs : e.protectedRefsOnly = true)
    (happrovals : e.environmentApprovalsRequired = true) :
    CiWorkflowPolicyConstrained e := by
  exact And.intro hreview (And.intro htrusted (And.intro hrefs happrovals))

end OpenCompliance.Controls
