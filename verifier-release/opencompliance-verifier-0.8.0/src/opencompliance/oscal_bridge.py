from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .example_specs import FIXTURE_SPECS


@dataclass(frozen=True)
class NormalizedObligation:
    control_id: str
    title: str
    statement: str
    implementation_state: str
    mapping_targets: list[str]


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text())


def _fixture_version(fixture_root: Path) -> str:
    return FIXTURE_SPECS[fixture_root.name].verifier_version.split("/")[-1]


def _catalog_controls(catalog: dict[str, Any]) -> dict[str, dict[str, Any]]:
    controls: dict[str, dict[str, Any]] = {}
    for group in catalog["catalog"]["groups"]:
        for control in group.get("controls", []):
            controls[control["id"]] = control
    return controls


def _mapping_targets(mapping_collection: dict[str, Any]) -> dict[str, list[str]]:
    mapping_targets: dict[str, list[str]] = {}
    for mapping in mapping_collection["mapping-collection"]["mappings"][0]["maps"]:
        source_ids = [source["id-ref"] for source in mapping["sources"]]
        target_ids = sorted(target["id-ref"] for target in mapping["targets"])
        for source_id in source_ids:
            mapping_targets[source_id] = target_ids
    return mapping_targets


def _implementation_state(requirement: dict[str, Any]) -> str:
    by_components = requirement.get("by-components", [])
    if by_components:
        status = by_components[0].get("implementation-status", {})
        return status.get("state", "implemented")
    if requirement.get("statements"):
        return "documented"
    return "implemented"


def normalize_oscal_fixture(fixture_root: Path) -> list[NormalizedObligation]:
    fixture = fixture_root.name
    oscal_root = fixture_root / "oscal"
    mapping_name = {
        "minimal": "iso27001-soc2-family-overlap-mapping.json",
        "failed": "iso27001-soc2-family-overlap-mapping.json",
        "medium": "iso27001-soc2-irap-gdpr-family-overlap-mapping.json",
        "stale": "iso27001-soc2-family-overlap-mapping.json",
        "issued": "iso27001-soc2-irap-family-overlap-mapping.json",
        "cyber-baseline": "cyber-essentials-baseline-family-overlap-mapping.json",
        "ai-governance": "ai-governance-family-overlap-mapping.json",
    }[fixture]

    catalog = _load_json(oscal_root / f"opencompliance-{fixture}-catalog.json")
    profile = _load_json(oscal_root / f"exampleco-{fixture}-profile.json")
    ssp = _load_json(oscal_root / f"exampleco-{fixture}-ssp.json")
    mapping_collection = _load_json(oscal_root / mapping_name)

    catalog_controls = _catalog_controls(catalog)
    selected_ids = profile["profile"]["imports"][0]["include-controls"][0]["with-ids"]
    implemented_requirements = {
        requirement["control-id"]: _implementation_state(requirement)
        for requirement in ssp["system-security-plan"]["control-implementation"]["implemented-requirements"]
    }
    mapping_targets = _mapping_targets(mapping_collection)

    obligations: list[NormalizedObligation] = []
    for control_id in selected_ids:
        if control_id not in catalog_controls:
            raise ValueError(f"catalog is missing selected control {control_id}")
        if control_id not in implemented_requirements:
            raise ValueError(f"ssp is missing implemented requirement for {control_id}")
        if control_id not in mapping_targets:
            raise ValueError(f"mapping collection is missing source mapping for {control_id}")

        control = catalog_controls[control_id]
        statement = ""
        for part in control.get("parts", []):
            if part.get("name") == "statement":
                statement = part.get("prose", "")
                break
        obligations.append(
            NormalizedObligation(
                control_id=control_id,
                title=control["title"],
                statement=statement,
                implementation_state=implemented_requirements[control_id],
                mapping_targets=mapping_targets[control_id],
            )
        )
    return obligations


def generate_assessment_results(fixture_root: Path, proof_bundle: dict[str, Any]) -> dict[str, Any]:
    spec = FIXTURE_SPECS[fixture_root.name]
    obligations = normalize_oscal_fixture(fixture_root)
    reviewed_controls = [{"control-id": obligation.control_id} for obligation in obligations]

    observations = []
    observation_index = 1
    for claim in proof_bundle["claims"]:
        if claim["result"] == "judgment_required":
            continue
        if claim["result"] == "evidence_missing":
            remarks = f"{claim['claimId']} is blocked because no typed evidence is attached."
        elif claim["result"] == "stale_evidence":
            remarks = f"{claim['claimId']} is blocked because {', '.join(claim['evidenceRefs'])} expired before this verification run."
        elif claim["result"] == "failed":
            remarks = f"{claim['claimId']} failed from {', '.join(claim['evidenceRefs'])}."
        elif claim["evidenceRefs"]:
            remarks = f"{claim['claimId']} {claim['result']} from {', '.join(claim['evidenceRefs'])}."
        else:
            remarks = f"{claim['claimId']} {claim['result']}."
        observations.append(
            {
                "uuid": f"oc-{fixture_root.name}-observation-{observation_index:03d}",
                "title": f"Observation for {claim['claimId']}",
                "description": claim["basis"],
                "methods": ["EXAMINE"],
                "types": ["observation"],
                "collected": spec.generated_at,
                "remarks": remarks,
            }
        )
        observation_index += 1

    fixture_title = fixture_root.name.capitalize()
    return {
        "assessment-results": {
            "uuid": f"oc-{fixture_root.name}-assessment-results",
            "metadata": {
                "title": f"ExampleCo {fixture_title} Corridor Assessment Results",
                "published": spec.generated_at,
                "last-modified": spec.generated_at,
                "version": _fixture_version(fixture_root),
                "oscal-version": "1.1.3",
                "remarks": "Synthetic assessment-results style output derived from the ExampleCo public proof bundle.",
            },
            "import-ap": {
                "href": f"./exampleco-{fixture_root.name}-assessment-plan.json"
            },
            "results": [
                {
                    "uuid": f"oc-{fixture_root.name}-assessment-result-001",
                    "title": f"ExampleCo {fixture_root.name} corridor result",
                    "description": "Result set derived from the public ExampleCo proof bundle.",
                    "start": spec.generated_at,
                    "end": spec.generated_at,
                    "reviewed-controls": {
                        "control-selections": [
                            {
                                "include-controls": reviewed_controls
                            }
                        ]
                    },
                    "observations": observations,
                }
            ],
            "back-matter": {
                "resources": [
                    {
                        "uuid": f"oc-{fixture_root.name}-proof-bundle-resource",
                        "title": "ExampleCo proof bundle",
                        "rlinks": [
                            {
                                "href": "../proof-bundle.json"
                            }
                        ],
                    },
                    {
                        "uuid": f"oc-{fixture_root.name}-trust-surface-resource",
                        "title": "ExampleCo trust-surface report",
                        "rlinks": [
                            {
                                "href": "../trust-surface-report.md"
                            }
                        ],
                    },
                ]
            },
        }
    }
