from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable


RouteKind = str
VerificationStatus = str


@dataclass(frozen=True)
class FrameworkMapping:
    framework: str
    family: str
    control_id: str | None = None

    def to_json(self) -> dict[str, str]:
        data = {
            "framework": self.framework,
            "family": self.family,
        }
        if self.control_id:
            data["controlId"] = self.control_id
        return data


@dataclass(frozen=True)
class EvidenceClaim:
    claim_id: str
    claim_type: str
    actor_type: str
    actor_role: str | None
    signer_type: str | None
    signer_role: str | None
    trust_policy_ref: str | None
    payload: dict[str, Any]
    mappings: list[FrameworkMapping]
    raw: dict[str, Any]


Predicate = Callable[[EvidenceClaim], bool]


@dataclass(frozen=True)
class VerificationItemSpec:
    claim_id: str
    title: str
    route: RouteKind
    expected_claim_type: str | None
    control_refs: list[str]
    default_framework_mappings: list[FrameworkMapping]
    basis_when_present: str | None = None
    basis_when_missing: str | None = None
    basis_when_stale: str | None = None
    basis_when_failed: str | None = None
    predicate: Predicate | None = None
    classification_rationale: str = ""


@dataclass(frozen=True)
class MixedControlSpec:
    control_id: str
    title: str
    rationale: str
    sub_claim_ids: list[str]


@dataclass(frozen=True)
class FixtureSpec:
    fixture_name: str
    bundle_id: str
    generated_at: str
    verifier_version: str
    bundle_scope_note: str
    next_actions: list[str]
    receipt_id: str
    receipt_issued_at: str
    receipt_note: str
    revocation_id: str
    artifact_id: str
    revoked_at: str
    revocation_reason: str
    trust_report_heading: str
    trust_report_why_lines: list[str]
    mixed_controls: list[MixedControlSpec] = field(default_factory=list)
    items: list[VerificationItemSpec] = field(default_factory=list)


@dataclass(frozen=True)
class ClassificationRecord:
    claim_id: str
    route: RouteKind
    title: str
    control_refs: list[str]
    rationale: str


@dataclass(frozen=True)
class VerificationClaim:
    claim_id: str
    title: str
    result: VerificationStatus
    framework_mappings: list[FrameworkMapping]
    control_refs: list[str]
    evidence_refs: list[str]
    basis: str

    def to_json(self) -> dict[str, Any]:
        return {
            "claimId": self.claim_id,
            "title": self.title,
            "result": self.result,
            "frameworkMappings": [mapping.to_json() for mapping in self.framework_mappings],
            "controlRefs": self.control_refs,
            "evidenceRefs": self.evidence_refs,
            "basis": self.basis,
        }


@dataclass(frozen=True)
class PunchListItem:
    claim_id: str
    title: str
    issue_type: str
    route: RouteKind
    required_claim_type: str | None
    framework_mappings: list[FrameworkMapping]
    control_refs: list[str]
    required_action: str
    reason: str

    def to_json(self) -> dict[str, Any]:
        data = {
            "claimId": self.claim_id,
            "title": self.title,
            "issueType": self.issue_type,
            "route": self.route,
            "frameworkMappings": [mapping.to_json() for mapping in self.framework_mappings],
            "controlRefs": self.control_refs,
            "requiredAction": self.required_action,
            "reason": self.reason,
        }
        if self.required_claim_type is not None:
            data["requiredClaimType"] = self.required_claim_type
        return data
