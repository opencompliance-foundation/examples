from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .actor_ontology import INDEPENDENT_WITNESS_POLICY_ID, validate_registered_identity
from .artifacts import artifact_sha256_from_path, pretty_json_text, sha256_json, sha256_text
from .evidence import EvidenceRegistry
from .example_specs import FIXTURE_SPECS
from .freshness import claim_is_stale
from .legallean_runtime import runtime_results_for_fixture
from .models import ClassificationRecord, FixtureSpec, FrameworkMapping, PunchListItem, VerificationClaim
from .oscal_bridge import generate_assessment_results, normalize_oscal_fixture
from .oscal import load_catalog_control_ids, load_profile_control_ids
from .paths import find_repo_root
from .proof_runner import run_lean_batch


def _load_profile(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text())


def select_fixture_spec(fixture_root: Path) -> FixtureSpec:
    fixture_name = fixture_root.name
    try:
        return FIXTURE_SPECS[fixture_name]
    except KeyError as exc:
        raise ValueError(f"Unsupported fixture name: {fixture_name}") from exc


def classify_fixture(fixture_root: Path) -> list[ClassificationRecord]:
    spec = select_fixture_spec(fixture_root)
    return [
        ClassificationRecord(
            claim_id=item.claim_id,
            route=item.route,
            title=item.title,
            control_refs=item.control_refs,
            rationale=item.classification_rationale,
        )
        for item in spec.items
    ]


def generate_classification_result(fixture_root: Path) -> dict[str, Any]:
    spec = select_fixture_spec(fixture_root)
    profile = _load_profile(fixture_root / "profile.json")
    repo_root = find_repo_root(fixture_root)
    boundaries = json.loads((repo_root / "open-specs" / "control-boundaries.json").read_text())
    boundaries_by_id = {control["controlId"]: control for control in boundaries["controls"]}

    route_summary = {
        "decidable": 0,
        "attestation": 0,
        "judgment": 0,
    }
    items = []
    items_by_id: dict[str, dict[str, Any]] = {}
    for item in spec.items:
        route_summary[item.route] = route_summary.get(item.route, 0) + 1
        lean_backed = any(
            boundaries_by_id.get(control_ref, {}).get("lean") is not None
            for control_ref in item.control_refs
        )
        item_json = {
            "claimId": item.claim_id,
            "title": item.title,
            "route": item.route,
            "controlRefs": item.control_refs,
            "expectedClaimType": item.expected_claim_type,
            "evidenceRequired": item.expected_claim_type is not None,
            "leanBacked": lean_backed,
            "rationale": item.classification_rationale,
        }
        items.append(item_json)
        items_by_id[item.claim_id] = item_json

    classification_result = {
        "classificationResultId": f"{spec.bundle_id}-classification",
        "generatedAt": spec.generated_at,
        "bundleId": spec.bundle_id,
        "verifierVersion": spec.verifier_version,
        "organisation": profile["organisation"],
        "profileId": profile["profileId"],
        "routeSummary": route_summary,
        "items": items,
        "note": "Synthetic persisted routing artifact for the OpenCompliance prove/attest/judgment split.",
    }
    if spec.mixed_controls:
        mixed_controls = []
        for mixed_control in spec.mixed_controls:
            boundary = boundaries_by_id.get(mixed_control.control_id)
            if boundary is None:
                raise ValueError(f"Missing mixed control boundary for {mixed_control.control_id}")
            decomposition_summary = {
                "decidable": 0,
                "attestation": 0,
                "judgment": 0,
            }
            sub_obligations = []
            for claim_id in mixed_control.sub_claim_ids:
                item_json = items_by_id.get(claim_id)
                if item_json is None:
                    raise ValueError(f"Missing mixed control sub-obligation {claim_id} in {mixed_control.control_id}")
                decomposition_summary[item_json["route"]] += 1
                sub_obligations.append(item_json)
            mixed_controls.append(
                {
                    "controlId": mixed_control.control_id,
                    "title": mixed_control.title,
                    "controlRefs": [mixed_control.control_id],
                    "frameworkMappings": boundary.get("sourceMappings", []),
                    "rationale": mixed_control.rationale,
                    "decompositionSummary": decomposition_summary,
                    "subObligations": sub_obligations,
                }
            )
        classification_result["mixedControls"] = mixed_controls
    return classification_result


def _framework_mappings_for_item(item, evidence_ref, registry: EvidenceRegistry) -> list[FrameworkMapping]:
    if evidence_ref is None:
        return item.default_framework_mappings
    return registry.get(evidence_ref).mappings


def _basis_for_result(item, result: str) -> str:
    if result in {"proved", "attested"}:
        return item.basis_when_present or ""
    if result == "evidence_missing":
        return item.basis_when_missing or ""
    if result == "judgment_required":
        return item.basis_when_missing or ""
    if result == "failed":
        return item.basis_when_failed or ""
    if result == "stale_evidence":
        return (
            item.basis_when_stale
            or f"The referenced {item.expected_claim_type} evidence exists but expired before this verification run."
        )
    raise ValueError(f"Unsupported verification result {result} for {item.claim_id}")


def _result_from_item(item, registry: EvidenceRegistry, generated_at: str) -> tuple[str, list[str], str, list[FrameworkMapping]]:
    if item.route == "judgment":
        return "judgment_required", [], item.basis_when_missing or "", item.default_framework_mappings

    evidence = registry.by_type(item.expected_claim_type or "")
    if not evidence:
        return "evidence_missing", [], item.basis_when_missing or "", item.default_framework_mappings

    selected = evidence[0]
    mappings = _framework_mappings_for_item(item, selected.claim_id, registry)
    if claim_is_stale(selected, generated_at):
        return (
            "stale_evidence",
            [selected.claim_id],
            item.basis_when_stale
            or f"The referenced {selected.claim_type} evidence exists but expired before this verification run.",
            mappings,
        )
    if item.predicate is None:
        raise ValueError(f"Missing predicate for non-judgment item {item.claim_id}")
    if not item.predicate(selected):
        return "failed", [selected.claim_id], item.basis_when_failed or "", mappings
    result = "proved" if item.route == "decidable" else "attested"
    return result, [selected.claim_id], item.basis_when_present or "", mappings


def generate_proof_bundle(fixture_root: Path) -> dict[str, Any]:
    spec = select_fixture_spec(fixture_root)
    profile = _load_profile(fixture_root / "profile.json")
    registry = EvidenceRegistry.from_path(fixture_root / "evidence-claims.json")
    runtime_results = runtime_results_for_fixture(fixture_root, spec, registry)
    runtime_consumed_claims: list[str] = []
    runtime_consumed_slots = sorted({entry["slot"] for entry in runtime_results.values()})

    claims = []
    summary = {
        "proved": 0,
        "attested": 0,
        "failed": 0,
        "staleEvidence": 0,
        "judgmentRequired": 0,
        "evidenceMissing": 0,
    }
    for item in spec.items:
        runtime_result = runtime_results.get(item.claim_id)
        if runtime_result is not None:
            result = runtime_result["result"]
            evidence_refs = runtime_result["evidenceRefs"]
            basis = _basis_for_result(item, result)
            mappings = _framework_mappings_for_item(item, evidence_refs[0] if evidence_refs else None, registry)
            runtime_consumed_claims.append(item.claim_id)
        else:
            result, evidence_refs, basis, mappings = _result_from_item(item, registry, spec.generated_at)
        claims.append(
            VerificationClaim(
                claim_id=item.claim_id,
                title=item.title,
                result=result,
                framework_mappings=mappings,
                control_refs=item.control_refs,
                evidence_refs=evidence_refs,
                basis=basis,
            )
        )
        if result == "judgment_required":
            summary["judgmentRequired"] += 1
        elif result == "evidence_missing":
            summary["evidenceMissing"] += 1
        elif result == "stale_evidence":
            summary["staleEvidence"] += 1
        else:
            summary[result] += 1

    bundle = {
        "bundleId": spec.bundle_id,
        "generatedAt": spec.generated_at,
        "verifierVersion": spec.verifier_version,
        "organisation": profile["organisation"],
        "profileId": profile["profileId"],
        "frameworkIntent": profile["frameworkIntent"],
        "scope": {
            **profile["scope"],
            "note": spec.bundle_scope_note,
        },
        "claims": [claim.to_json() for claim in claims],
        "summary": summary,
        "nextActions": spec.next_actions,
    }
    bundle["proofRunner"] = run_lean_batch(
        fixture_root,
        bundle,
        runtime_context={
            "runtimeConsumedClaims": runtime_consumed_claims,
            "runtimeConsumedSlots": runtime_consumed_slots,
            "fullMinimalSolverAgreement": runtime_consumed_slots
            == ["identity", "logging", "policy", "restore", "training"]
            and len(runtime_consumed_claims) == len(spec.items),
            "pythonVerdictLayerReplaced": len(runtime_consumed_claims) == len(spec.items),
        },
    )
    return bundle


def generate_trust_surface_report(fixture_root: Path, proof_bundle: dict[str, Any]) -> str:
    spec = select_fixture_spec(fixture_root)
    categories = {
        "proved": [],
        "attested": [],
        "failed": [],
        "stale_evidence": [],
        "judgment_required": [],
        "evidence_missing": [],
    }
    for claim in proof_bundle["claims"]:
        categories[claim["result"]].append(claim["title"])

    def _count_line(count: int, label: str) -> str:
        suffix = "claim" if count == 1 else "claims"
        return f"- `{count}` {label} {suffix}"

    def _typed_boundary_lines() -> list[str]:
        typed_boundary = proof_bundle.get("proofRunner", {}).get("typedBoundaryLayer")
        if not typed_boundary:
            return []

        runtime_status = typed_boundary["runtimeStatus"]
        lines = [
            "## Typed Boundary Layer",
            "",
            f"The current public corridor uses `{typed_boundary['source']}` as its typed boundary vocabulary.",
            "",
            f"- Dependency package: `{typed_boundary['dependency']['package']}`",
            "- Live typed modules:",
        ]
        for module in typed_boundary["typedModules"]:
            covers = ", ".join(f"`{entry}`" for entry in module["covers"])
            lines.append(f"- `{module['module']}` covers {covers}")

        runtime_consumed_claims = typed_boundary.get("runtimeConsumedClaims", [])
        lines.extend(
            [
                "",
                f"- Runtime-consumed claims: `{len(runtime_consumed_claims)}`",
                "- Runtime status:",
                f"- typed control results live: `{str(runtime_status['typedControlResultsLive']).lower()}`",
                f"- risk-acceptance defeasibility live: `{str(runtime_status['riskAcceptanceDefeasibilityLive']).lower()}`",
                f"- discretionary-term typing live: `{str(runtime_status['discretionaryTermTypingLive']).lower()}`",
                f"- full minimal solver agreement proved: `{str(runtime_status['fullMinimalSolverAgreement']).lower()}`",
                f"- Python verdict layer replaced: `{str(runtime_status['pythonVerdictLayerReplaced']).lower()}`",
            ]
        )
        return lines

    lines = [
        spec.trust_report_heading,
        "",
        f"**Bundle:** `{proof_bundle['bundleId']}`  ",
        f"**Profile:** `{proof_bundle['profileId']}`",
        "",
        "## Executive Summary",
        "",
        "This synthetic example shows the intended OpenCompliance split:"
        if spec.fixture_name == "minimal"
        else "This synthetic example shows a wider OpenCompliance corridor without pretending the corridor is complete:",
        "",
        _count_line(proof_bundle["summary"]["proved"], "proved"),
        _count_line(proof_bundle["summary"]["attested"], "attested"),
        _count_line(proof_bundle["summary"]["failed"], "failed"),
        _count_line(proof_bundle["summary"]["staleEvidence"], "stale-evidence"),
        _count_line(proof_bundle["summary"]["judgmentRequired"], "judgment-required"),
        _count_line(proof_bundle["summary"]["evidenceMissing"], "evidence-missing"),
        "",
        "## Proved",
        "",
    ]
    lines.extend(f"- {title}" for title in categories["proved"])
    lines.extend(["", "## Attested", ""])
    lines.extend(f"- {title}" for title in categories["attested"])
    lines.extend(["", "## Failed", ""])
    lines.extend(f"- {title}" for title in categories["failed"])
    lines.extend(["", "## Stale Evidence", ""])
    lines.extend(f"- {title}" for title in categories["stale_evidence"])
    lines.extend(["", "## Judgment Required", ""])
    lines.extend(f"- {title}" for title in categories["judgment_required"])
    lines.extend(["", "## Evidence Missing", ""])
    lines.extend(f"- {title}" for title in categories["evidence_missing"])
    typed_boundary_lines = _typed_boundary_lines()
    if typed_boundary_lines:
        lines.extend(["", *typed_boundary_lines])
    lines.extend(["", "## Why This Example Exists", ""])
    lines.extend(spec.trust_report_why_lines)
    return "\n".join(lines) + "\n"


def _certificate_eligible(proof_bundle: dict[str, Any]) -> bool:
    summary = proof_bundle["summary"]
    return (
        summary["failed"] == 0
        and summary["staleEvidence"] == 0
        and summary["judgmentRequired"] == 0
        and summary["evidenceMissing"] == 0
    )


def generate_punch_list(fixture_root: Path, proof_bundle: dict[str, Any]) -> dict[str, Any]:
    spec = select_fixture_spec(fixture_root)
    item_by_claim_id = {item.claim_id: item for item in spec.items}
    items: list[PunchListItem] = []

    for claim in proof_bundle["claims"]:
        if claim["result"] == "evidence_missing":
            item = item_by_claim_id[claim["claimId"]]
            issue_type = "missing_machine_evidence" if item.route == "decidable" else "missing_attestation"
            required_action = "attach_typed_evidence_claim" if item.route == "decidable" else "attach_signed_attestation"
            items.append(
                PunchListItem(
                    claim_id=claim["claimId"],
                    title=claim["title"],
                    issue_type=issue_type,
                    route=item.route,
                    required_claim_type=item.expected_claim_type,
                    framework_mappings=item.default_framework_mappings or [
                        FrameworkMapping(
                            framework=mapping["framework"],
                            family=mapping["family"],
                            control_id=mapping.get("controlId"),
                        )
                        for mapping in claim["frameworkMappings"]
                    ],
                    control_refs=claim["controlRefs"],
                    required_action=required_action,
                    reason=claim["basis"],
                )
            )
        elif claim["result"] == "stale_evidence":
            item = item_by_claim_id[claim["claimId"]]
            issue_type = "stale_machine_evidence" if item.route == "decidable" else "stale_attestation"
            required_action = "refresh_typed_evidence_claim" if item.route == "decidable" else "renew_signed_attestation"
            items.append(
                PunchListItem(
                    claim_id=claim["claimId"],
                    title=claim["title"],
                    issue_type=issue_type,
                    route=item.route,
                    required_claim_type=item.expected_claim_type,
                    framework_mappings=item.default_framework_mappings or [
                        FrameworkMapping(
                            framework=mapping["framework"],
                            family=mapping["family"],
                            control_id=mapping.get("controlId"),
                        )
                        for mapping in claim["frameworkMappings"]
                    ],
                    control_refs=claim["controlRefs"],
                    required_action=required_action,
                    reason=claim["basis"],
                )
            )
        elif claim["result"] == "failed":
            item = item_by_claim_id[claim["claimId"]]
            issue_type = "failing_machine_evidence" if item.route == "decidable" else "failing_attestation"
            required_action = "fix_machine_state" if item.route == "decidable" else "replace_invalid_attestation"
            items.append(
                PunchListItem(
                    claim_id=claim["claimId"],
                    title=claim["title"],
                    issue_type=issue_type,
                    route=item.route,
                    required_claim_type=item.expected_claim_type,
                    framework_mappings=item.default_framework_mappings or [
                        FrameworkMapping(
                            framework=mapping["framework"],
                            family=mapping["family"],
                            control_id=mapping.get("controlId"),
                        )
                        for mapping in claim["frameworkMappings"]
                    ],
                    control_refs=claim["controlRefs"],
                    required_action=required_action,
                    reason=claim["basis"],
                )
            )
        elif claim["result"] == "judgment_required":
            item = item_by_claim_id[claim["claimId"]]
            items.append(
                PunchListItem(
                    claim_id=claim["claimId"],
                    title=claim["title"],
                    issue_type="human_judgment_required",
                    route=item.route,
                    required_claim_type=item.expected_claim_type,
                    framework_mappings=[
                        FrameworkMapping(
                            framework=mapping["framework"],
                            family=mapping["family"],
                            control_id=mapping.get("controlId"),
                        )
                        for mapping in claim["frameworkMappings"]
                    ],
                    control_refs=claim["controlRefs"],
                    required_action="obtain_human_review",
                    reason=claim["basis"],
                )
            )

    return {
        "punchListId": f"{proof_bundle['bundleId']}-punch-list",
        "generatedAt": spec.generated_at,
        "bundleId": proof_bundle["bundleId"],
        "verifierVersion": spec.verifier_version,
        "organisation": proof_bundle["organisation"],
        "profileId": proof_bundle["profileId"],
        "blockingIssueCount": len(items),
        "blockingIssues": [item.to_json() for item in items],
        "note": "Synthetic typed remediation artifact derived from the deterministic proof bundle.",
    }


def generate_certificate(
    fixture_root: Path,
    proof_bundle: dict[str, Any],
    trust_surface_report: str,
) -> dict[str, Any]:
    spec = select_fixture_spec(fixture_root)
    if not _certificate_eligible(proof_bundle):
        raise ValueError(
            "certificate generation requires a proof bundle with no failed, stale, judgment, or missing-evidence blockers"
        )

    control_refs = sorted(
        {
            control_ref
            for claim in proof_bundle["claims"]
            for control_ref in claim["controlRefs"]
        }
    )
    return {
        "certificateId": spec.artifact_id,
        "status": "issued",
        "issuedAt": spec.generated_at,
        "bundleId": proof_bundle["bundleId"],
        "verifierVersion": spec.verifier_version,
        "organisation": proof_bundle["organisation"],
        "profileId": proof_bundle["profileId"],
        "scope": proof_bundle["scope"],
        "controlRefs": control_refs,
        "coverage": proof_bundle["summary"],
        "proofBundleSha256": sha256_json(proof_bundle),
        "trustSurfaceSha256": sha256_text(trust_surface_report),
        "note": "Synthetic narrow-corridor certificate artifact for an example bundle with no blocking gaps.",
    }


def generate_verification_result(
    fixture_root: Path,
    proof_bundle: dict[str, Any],
    trust_surface_report: str,
    outcome_artifact_name: str,
    outcome_artifact: dict[str, Any],
) -> dict[str, Any]:
    spec = select_fixture_spec(fixture_root)
    outcome = "certificate_issued" if outcome_artifact_name == "certificate.json" else "punch_list_issued"
    return {
        "verificationResultId": f"{proof_bundle['bundleId']}-result",
        "generatedAt": spec.generated_at,
        "bundleId": proof_bundle["bundleId"],
        "verifierVersion": spec.verifier_version,
        "organisation": proof_bundle["organisation"],
        "profileId": proof_bundle["profileId"],
        "outcome": outcome,
        "proofBundleSha256": sha256_json(proof_bundle),
        "trustSurfaceSha256": sha256_text(trust_surface_report),
        "outcomeArtifact": {
            "path": outcome_artifact_name,
            "sha256": sha256_json(outcome_artifact),
        },
        "blockingIssueCount": (
            proof_bundle["summary"]["failed"]
            + proof_bundle["summary"]["staleEvidence"]
            + proof_bundle["summary"]["judgmentRequired"]
            + proof_bundle["summary"]["evidenceMissing"]
        ),
    }


def _replay_material_inputs(fixture_root: Path) -> list[dict[str, str]]:
    fixture_name = fixture_root.name
    catalog_name = f"oscal/opencompliance-{fixture_name}-catalog.json"
    profile_name = f"oscal/exampleco-{fixture_name}-profile.json"
    paths = [
        ("profile", "profile.json"),
        ("evidence_claims", "evidence-claims.json"),
        ("oscal_catalog", catalog_name),
        ("oscal_profile", profile_name),
    ]
    return [
        {
            "artifactType": artifact_type,
            "path": relative_path,
            "sha256": artifact_sha256_from_path(fixture_root / relative_path),
        }
        for artifact_type, relative_path in paths
    ]


def generate_replay_bundle(
    fixture_root: Path,
    proof_bundle: dict[str, Any],
    trust_surface_report: str,
    outcome_artifact_name: str,
    outcome_artifact: dict[str, Any],
    verification_result: dict[str, Any],
) -> dict[str, Any]:
    spec = select_fixture_spec(fixture_root)
    expected_outputs = [
        {
            "artifactType": "proof_bundle",
            "path": "proof-bundle.json",
            "sha256": sha256_json(proof_bundle),
        },
        {
            "artifactType": "trust_surface_report",
            "path": "trust-surface-report.md",
            "sha256": sha256_text(trust_surface_report),
        },
        {
            "artifactType": "verification_result",
            "path": "verification-result.json",
            "sha256": sha256_json(verification_result),
        },
        {
            "artifactType": "certificate" if outcome_artifact_name == "certificate.json" else "punch_list",
            "path": outcome_artifact_name,
            "sha256": sha256_json(outcome_artifact),
        },
    ]
    return {
        "replayBundleId": f"{proof_bundle['bundleId']}-replay",
        "generatedAt": spec.generated_at,
        "bundleId": proof_bundle["bundleId"],
        "verifierVersion": spec.verifier_version,
        "fixture": spec.fixture_name,
        "replayCommand": [
            "python3",
            "scripts/verify_fixture.py",
            "--fixture-root",
            f"fixtures/public/{spec.fixture_name}",
            "--check",
        ],
        "materialInputs": _replay_material_inputs(fixture_root),
        "expectedOutputs": expected_outputs,
        "note": "Synthetic replay contract for deterministic reruns of the public example corridor.",
    }


def generate_witness_receipt(
    fixture_root: Path,
    replay_bundle: dict[str, Any],
) -> dict[str, Any]:
    spec = select_fixture_spec(fixture_root)
    checked_artifacts = replay_bundle["materialInputs"] + replay_bundle["expectedOutputs"]
    witness = {
        "witnessId": "oc-synthetic-independent-witness",
        "witnessType": "independent_witness",
        "witnessRole": "independent_replay_witness",
        "trustPolicyId": INDEPENDENT_WITNESS_POLICY_ID,
    }
    validate_registered_identity(
        witness["witnessId"],
        surface="witness_receipt",
        actor_type=witness["witnessType"],
        role=witness["witnessRole"],
        trust_policy_id=witness["trustPolicyId"],
    )
    receipt = {
        "receiptId": spec.receipt_id,
        "issuedAt": spec.receipt_issued_at,
        "bundleId": spec.bundle_id,
        "verifierVersion": spec.verifier_version,
        "replayBundleId": replay_bundle["replayBundleId"],
        "replayResult": "exact_match",
        "witness": witness,
        "checkedArtifacts": checked_artifacts,
        "note": spec.receipt_note,
    }
    return receipt


def generate_revocation(fixture_root: Path) -> dict[str, Any]:
    spec = select_fixture_spec(fixture_root)
    return {
        "revocationId": spec.revocation_id,
        "artifactType": "certificate",
        "artifactId": spec.artifact_id,
        "revokedAt": spec.revoked_at,
        "reason": spec.revocation_reason,
        "supersededBy": spec.bundle_id,
    }


def verify_fixture_consistency(fixture_root: Path) -> dict[str, str]:
    spec = select_fixture_spec(fixture_root)
    classification_result = generate_classification_result(fixture_root)
    proof_bundle = generate_proof_bundle(fixture_root)
    assessment_results = generate_assessment_results(fixture_root, proof_bundle)
    trust_surface = generate_trust_surface_report(fixture_root, proof_bundle)
    if _certificate_eligible(proof_bundle):
        outcome_artifact_name = "certificate.json"
        outcome_artifact = generate_certificate(fixture_root, proof_bundle, trust_surface)
    else:
        outcome_artifact_name = "punch-list.json"
        outcome_artifact = generate_punch_list(fixture_root, proof_bundle)
    verification_result = generate_verification_result(
        fixture_root,
        proof_bundle,
        trust_surface,
        outcome_artifact_name,
        outcome_artifact,
    )
    replay_bundle = generate_replay_bundle(
        fixture_root,
        proof_bundle,
        trust_surface,
        outcome_artifact_name,
        outcome_artifact,
        verification_result,
    )
    witness = generate_witness_receipt(fixture_root, replay_bundle)
    revocation = generate_revocation(fixture_root)
    return {
        "classification-result.json": pretty_json_text(classification_result),
        "proof-bundle.json": pretty_json_text(proof_bundle),
        f"oscal/exampleco-{spec.fixture_name}-assessment-results.json": pretty_json_text(assessment_results),
        "trust-surface-report.md": trust_surface,
        "verification-result.json": pretty_json_text(verification_result),
        outcome_artifact_name: pretty_json_text(outcome_artifact),
        "replay-bundle.json": pretty_json_text(replay_bundle),
        "witness-receipt.json": pretty_json_text(witness),
        "revocation.json": pretty_json_text(revocation),
        "fixture": spec.fixture_name,
    }


def validate_oscal_linkage(fixture_root: Path) -> None:
    normalize_oscal_fixture(fixture_root)
    fixture_name = fixture_root.name
    catalog_path = fixture_root / "oscal" / f"opencompliance-{fixture_name}-catalog.json"
    profile_path = fixture_root / "oscal" / f"exampleco-{fixture_name}-profile.json"
    catalog_controls = load_catalog_control_ids(catalog_path)
    profile_controls = load_profile_control_ids(profile_path)
    if catalog_controls != profile_controls:
        raise ValueError(
            f"OSCAL catalog/profile mismatch for {fixture_name}: {sorted(catalog_controls)} != {sorted(profile_controls)}"
        )
