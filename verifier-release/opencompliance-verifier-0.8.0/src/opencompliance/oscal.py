from __future__ import annotations

import json
from pathlib import Path


def load_catalog_control_ids(catalog_path: Path) -> set[str]:
    data = json.loads(catalog_path.read_text())
    controls: set[str] = set()
    for group in data["catalog"]["groups"]:
        for control in group.get("controls", []):
            controls.add(control["id"])
    return controls


def load_profile_control_ids(profile_path: Path) -> set[str]:
    data = json.loads(profile_path.read_text())
    include_controls = data["profile"]["imports"][0]["include-controls"][0]["with-ids"]
    return set(include_controls)

