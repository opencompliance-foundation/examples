from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def _repo_root(path: Path) -> Path:
    resolved = path.resolve()
    if resolved.is_file():
        resolved = resolved.parent
    for candidate in [resolved, *resolved.parents]:
        if (candidate / "open-specs").exists() and (candidate / "src").exists():
            return candidate
    raise FileNotFoundError(f"could not locate OpenCompliance repo root from {path}")


def review_pilot_path(path: Path) -> Path:
    root = _repo_root(path)
    return root / "open-specs" / "review-pilots" / "exact-anchor-review-pilot.json"


def load_exact_anchor_review(path: Path) -> dict[str, Any]:
    return json.loads(review_pilot_path(path).read_text())


def summary_for_controls(path: Path, control_ids: list[str]) -> dict[str, Any]:
    pilot = load_exact_anchor_review(path)
    requested_ids = set(control_ids)
    selected_controls = [
        control
        for control in pilot["controls"]
        if control["controlId"] in requested_ids
    ]
    counts = {
        "public_source_reviewed": 0,
        "candidate_public_source_unreviewed": 0,
        "blocked_nonpublic_source_review": 0,
    }
    framework_counts: dict[str, dict[str, int]] = {}

    for control in selected_controls:
        for review in control["reviews"]:
            status = review["reviewStatus"]
            counts[status] = counts.get(status, 0) + 1
            framework = review["framework"]
            framework_counts.setdefault(
                framework,
                {
                    "public_source_reviewed": 0,
                    "candidate_public_source_unreviewed": 0,
                    "blocked_nonpublic_source_review": 0,
                },
            )
            framework_counts[framework][status] = framework_counts[framework].get(status, 0) + 1

    return {
        "pilotId": pilot["pilotId"],
        "controlsCovered": len(selected_controls),
        "statuses": counts,
        "frameworks": framework_counts,
    }
