from __future__ import annotations

from pathlib import Path

from .verifier import verify_fixture_consistency


def run_verify(fixture_root: Path) -> dict[str, str]:
    """Return the full deterministic artifact set for a synthetic fixture."""
    return verify_fixture_consistency(fixture_root)
