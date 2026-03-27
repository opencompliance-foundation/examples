from __future__ import annotations

import json
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .actor_ontology import INDEPENDENT_WITNESS_POLICY_ID, validate_registered_identity


RELEASE_ATTESTATION_SCHEMA_URL = "https://opencompliancefoundation.com/specs/schemas/release-attestation.schema.json"


@dataclass(frozen=True)
class ReleaseAttestationCheck:
    name: str
    command: tuple[str, ...]
    description: str

    def to_json(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "command": list(self.command),
            "description": self.description,
        }


def default_release_attestation_checks() -> tuple[ReleaseAttestationCheck, ...]:
    python = sys.executable
    return (
        ReleaseAttestationCheck(
            name="replay minimal corridor from bundled verifier",
            command=(python, "scripts/verify_fixture.py", "--fixture-root", "fixtures/public/minimal", "--check"),
            description="Replays the blocked minimal corridor directly from the shipped bundle.",
        ),
        ReleaseAttestationCheck(
            name="replay issued corridor from bundled verifier",
            command=(python, "scripts/verify_fixture.py", "--fixture-root", "fixtures/public/issued", "--check"),
            description="Replays the issued mixed corridor directly from the shipped bundle.",
        ),
        ReleaseAttestationCheck(
            name="validate bundled public examples",
            command=(python, "conformance/scripts/validate_public_examples.py", "--fixture", "all"),
            description="Runs the bundled public-example conformance validator against all shipped synthetic corridors.",
        ),
        ReleaseAttestationCheck(
            name="verify minimal transparency log",
            command=(
                python,
                "scripts/verify_transparency_log.py",
                "--log",
                "fixtures/public/minimal/transparency-log.json",
                "--proofs",
                "fixtures/public/minimal/inclusion-proofs.json",
            ),
            description="Checks append-only integrity for the minimal bundled corridor.",
        ),
        ReleaseAttestationCheck(
            name="verify issued transparency log",
            command=(
                python,
                "scripts/verify_transparency_log.py",
                "--log",
                "fixtures/public/issued/transparency-log.json",
                "--proofs",
                "fixtures/public/issued/inclusion-proofs.json",
            ),
            description="Checks append-only integrity for the issued bundled corridor.",
        ),
    )


def _cleanup_runtime_artifacts(bundle_root: Path) -> None:
    for path in bundle_root.rglob("__pycache__"):
        shutil.rmtree(path, ignore_errors=True)
    for path in bundle_root.rglob(".lake"):
        shutil.rmtree(path, ignore_errors=True)


def generate_release_attestation(
    bundle_root: Path,
    *,
    release_id: str,
    verifier_version: str,
    generated_at: str,
) -> dict[str, Any]:
    witness = {
        "witnessId": "oc-synthetic-release-witness",
        "witnessType": "independent_witness",
        "witnessRole": "independent_replay_witness",
        "trustPolicyId": INDEPENDENT_WITNESS_POLICY_ID,
    }
    validate_registered_identity(
        witness["witnessId"],
        surface="release_attestation",
        actor_type=witness["witnessType"],
        role=witness["witnessRole"],
        trust_policy_id=witness["trustPolicyId"],
    )
    checks_payload: list[dict[str, Any]] = []
    try:
        for check in default_release_attestation_checks():
            result = subprocess.run(
                check.command,
                cwd=bundle_root,
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode != 0:
                raise ValueError(
                    "Release attestation check failed for "
                    f"{release_id} ({check.name}).\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
                )
            summary = next(
                (line.strip() for line in reversed(result.stdout.splitlines()) if line.strip()),
                "check passed",
            )
            checks_payload.append(
                {
                    **check.to_json(),
                    "status": "verified",
                    "summary": summary,
                }
            )
    finally:
        _cleanup_runtime_artifacts(bundle_root)

    return {
        "$schema": RELEASE_ATTESTATION_SCHEMA_URL,
        "attestationId": f"{release_id}-attestation",
        "generatedAt": generated_at,
        "releaseId": release_id,
        "verifierVersion": verifier_version,
        "attestationScope": "portable_bundle_self_replay",
        "witness": witness,
        "checks": checks_payload,
        "note": (
            "Synthetic release attestation for the public verifier bundle. "
            "This proves bundle self-replay and transparency verification from the shipped bundle; "
            "it does not claim live CI provenance or production runner identity."
        ),
    }
