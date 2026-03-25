from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .artifacts import artifact_sha256_from_path, sha256_json


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text())


def _sort_unique(values: list[str]) -> list[str]:
    return sorted(set(values))


def _load_certificate_inputs(
    certificate_path: Path,
    profile_path: Path,
    proof_bundle_path: Path,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    certificate = _load_json(certificate_path)
    profile = _load_json(profile_path)
    proof_bundle = _load_json(proof_bundle_path)
    return certificate, profile, proof_bundle


def _impacted_claims(proof_bundle: dict[str, Any], source_change: dict[str, Any]) -> list[dict[str, Any]]:
    impacted_evidence_refs = {
        ref
        for change in source_change["changes"]
        for ref in change.get("impactedEvidenceRefs", [])
    }
    impacted_control_refs = {
        ref
        for change in source_change["changes"]
        for ref in change.get("impactedControlRefs", [])
    }

    impacted: list[dict[str, Any]] = []
    for claim in proof_bundle["claims"]:
        evidence_refs = set(claim["evidenceRefs"])
        control_refs = set(claim["controlRefs"])
        if evidence_refs & impacted_evidence_refs or control_refs & impacted_control_refs:
            impacted.append(claim)
    return impacted


def analyze_certificate_lifecycle(
    certificate_path: Path,
    profile_path: Path,
    proof_bundle_path: Path,
    source_change_path: Path,
    decision_policy: str = "revoke",
) -> dict[str, Any]:
    if decision_policy not in {"revoke", "re_verification_required"}:
        raise ValueError("decision_policy must be revoke or re_verification_required")

    certificate, profile, proof_bundle = _load_certificate_inputs(
        certificate_path,
        profile_path,
        proof_bundle_path,
    )
    source_change = _load_json(source_change_path)
    impacted_claims = _impacted_claims(proof_bundle, source_change)
    if not impacted_claims:
        raise ValueError("source change did not map to any impacted proof-bundle claims")

    all_claim_ids = [claim["claimId"] for claim in proof_bundle["claims"]]
    recheck_claim_ids = [claim["claimId"] for claim in impacted_claims]
    reused_claim_ids = [claim_id for claim_id in all_claim_ids if claim_id not in recheck_claim_ids]
    impacted_control_refs = _sort_unique(
        [
            control_ref
            for claim in impacted_claims
            for control_ref in claim["controlRefs"]
        ]
    )

    new_status = "revoked" if decision_policy == "revoke" else "re_verification_required"
    decision_reason = (
        "Impacted controls are outside the previous certificate's trusted state until a fresh verification run succeeds."
        if decision_policy == "re_verification_required"
        else "Fail-closed revocation after invalidating drift on previously covered controls."
    )
    emitted_events = ["ComplianceDriftDetected"]
    if new_status == "revoked":
        emitted_events.append("CertificateRevoked")

    return {
        "lifecycleEventId": f"{certificate['certificateId']}-lifecycle-{source_change['sourceChangeId']}",
        "generatedAt": source_change["occurredAt"],
        "certificateId": certificate["certificateId"],
        "organisation": certificate["organisation"],
        "profileId": certificate["profileId"],
        "frameworkIntent": profile["frameworkIntent"],
        "previousStatus": certificate["status"],
        "newStatus": new_status,
        "decisionReason": decision_reason,
        "sourceChangeId": source_change["sourceChangeId"],
        "sourceChange": source_change,
        "impactedControlRefs": impacted_control_refs,
        "impactedClaims": [
            {
                "claimId": claim["claimId"],
                "title": claim["title"],
                "previousResult": claim["result"],
                "controlRefs": claim["controlRefs"],
                "evidenceRefs": claim["evidenceRefs"],
                "nextAction": "recheck_claim",
            }
            for claim in impacted_claims
        ],
        "deltaRecheck": {
            "recheckClaims": recheck_claim_ids,
            "reusedClaims": reused_claim_ids,
            "avoidsFullRerun": bool(reused_claim_ids),
        },
        "lineage": {
            "certificateId": certificate["certificateId"],
            "previousBundleId": certificate["bundleId"],
            "history": [
                {
                    "status": certificate["status"],
                    "bundleId": certificate["bundleId"],
                    "artifactSha256": artifact_sha256_from_path(certificate_path),
                    "recordedAt": certificate["issuedAt"],
                },
                {
                    "status": new_status,
                    "sourceChangeId": source_change["sourceChangeId"],
                    "recordedAt": source_change["occurredAt"],
                },
            ],
        },
        "compositionBlocked": True,
        "emittedEvents": emitted_events,
        "proofBundleSha256": sha256_json(proof_bundle),
        "note": "Synthetic lifecycle decision derived from a normalized source-change event over a previously issued ExampleCo certificate.",
    }


def _ensure_same_framework_intent(profiles: list[dict[str, Any]]) -> list[str]:
    framework_sets = [tuple(profile["frameworkIntent"]) for profile in profiles]
    first = framework_sets[0]
    for current in framework_sets[1:]:
        if current != first:
            raise ValueError("component certificates do not share an identical framework intent")
    return list(first)


def compose_certificates(
    components: list[dict[str, Any]],
    composed_certificate_id: str,
    generated_at: str,
    scope: dict[str, Any],
    note: str,
) -> dict[str, Any]:
    if len(components) < 2:
        raise ValueError("at least two component certificates are required for composition")

    loaded: list[tuple[dict[str, Any], dict[str, Any], dict[str, Any]]] = []
    for component in components:
        certificate = _load_json(Path(component["certificatePath"]))
        profile = _load_json(Path(component["profilePath"]))
        if certificate["status"] != "issued":
            raise ValueError("only issued component certificates may be composed")
        loaded.append((component, certificate, profile))

    organisations = {certificate["organisation"] for _, certificate, _ in loaded}
    if len(organisations) != 1:
        raise ValueError("component certificates must belong to the same organisation")

    framework_intent = _ensure_same_framework_intent([profile for _, _, profile in loaded])
    control_refs = _sort_unique(
        [
            control_ref
            for _, certificate, _ in loaded
            for control_ref in certificate["controlRefs"]
        ]
    )
    coverage = {
        "proved": sum(certificate["coverage"]["proved"] for _, certificate, _ in loaded),
        "attested": sum(certificate["coverage"]["attested"] for _, certificate, _ in loaded),
        "judgmentRequired": sum(certificate["coverage"]["judgmentRequired"] for _, certificate, _ in loaded),
        "evidenceMissing": sum(certificate["coverage"]["evidenceMissing"] for _, certificate, _ in loaded),
    }

    return {
        "composedCertificateId": composed_certificate_id,
        "status": "issued",
        "generatedAt": generated_at,
        "organisation": next(iter(organisations)),
        "frameworkIntent": framework_intent,
        "scope": scope,
        "componentCertificates": [
            {
                "componentName": component["componentName"],
                "certificateId": certificate["certificateId"],
                "bundleId": certificate["bundleId"],
                "profileId": certificate["profileId"],
                "controlRefs": certificate["controlRefs"],
                "proofBundleSha256": certificate["proofBundleSha256"],
            }
            for component, certificate, _ in loaded
        ],
        "controlRefs": control_refs,
        "coverage": coverage,
        "compositionRule": "All component certificates must be issued for the same organisation and identical framework intent.",
        "note": note,
    }
