from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any


def _repo_root(path: Path) -> Path:
    resolved = path.resolve()
    if resolved.is_file():
        resolved = resolved.parent
    for candidate in [resolved, *resolved.parents]:
        if (candidate / "internal" / "control-seed").exists() and (candidate / "src").exists():
            return candidate
    raise FileNotFoundError(f"could not locate OpenCompliance repo root from {path}")


def decomposition_pilot_path(path: Path) -> Path:
    root = _repo_root(path)
    return root / "internal" / "control-seed" / "iso-soc2-seed-decomposition-pilot.json"


def framework_depth_report_path(path: Path, slug: str) -> Path:
    root = _repo_root(path)
    return root / "internal" / "control-seed" / "framework-depth" / f"{slug}.json"


def load_seed_decomposition_pilot(path: Path) -> dict[str, Any]:
    return json.loads(decomposition_pilot_path(path).read_text())


def load_framework_depth_report(path: Path, slug: str) -> dict[str, Any]:
    return json.loads(framework_depth_report_path(path, slug).read_text())


def summary_for_seed_controls(path: Path, seed_control_ids: list[str]) -> dict[str, Any]:
    pilot = load_seed_decomposition_pilot(path)
    requested_ids = set(seed_control_ids)
    selected_controls = [
        control for control in pilot["controls"] if control["seedControlId"] in requested_ids
    ]

    route_counts: Counter[str] = Counter()
    existing_claim_types: set[str] = set()
    planned_claim_types: set[str] = set()
    controls_with_existing_targets: set[str] = set()
    controls_requiring_new_targets: set[str] = set()
    future_target_ids: set[str] = set()

    for control in selected_controls:
        for atom in control["decomposition"]:
            route_counts[atom["route"]] += 1
            for claim_ref in atom["claimRefs"]:
                if claim_ref["schemaStatus"] == "existing":
                    existing_claim_types.add(claim_ref["claimType"])
                else:
                    planned_claim_types.add(claim_ref["claimType"])
            for target in atom["candidateTargets"]:
                if target["type"] == "existing_public_control":
                    controls_with_existing_targets.add(control["seedControlId"])
                else:
                    controls_requiring_new_targets.add(control["seedControlId"])
                    future_target_ids.add(target["id"])

    return {
        "pilotId": pilot["pilotId"],
        "seedControlsCovered": len(selected_controls),
        "atomicObligations": sum(len(control["decomposition"]) for control in selected_controls),
        "routeCounts": {
            "decidable": route_counts.get("decidable", 0),
            "attestation": route_counts.get("attestation", 0),
            "judgment": route_counts.get("judgment", 0),
        },
        "controlsWithExistingPublicTargets": len(controls_with_existing_targets),
        "controlsRequiringNewPublicTargets": len(controls_requiring_new_targets),
        "candidateFuturePublicControls": len(future_target_ids),
        "existingClaimTypesReferenced": len(existing_claim_types),
        "plannedClaimTypesReferenced": len(planned_claim_types),
    }
