from __future__ import annotations

import json
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .trust_roots import resolve_release_attestation_witness


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
    lean_root = bundle_root / "lean4-controls"
    if lean_root.exists():
        for path in lean_root.glob("tmp*"):
            if path.is_dir():
                shutil.rmtree(path, ignore_errors=True)
            elif path.exists():
                path.unlink()


def _is_transient_bundle_bootstrap_failure(stderr: str) -> bool:
    markers = (
        "Lean package bootstrap failed:",
        "external command 'git' exited with code",
    )
    return all(marker in stderr for marker in markers)


def _run_attestation_check(bundle_root: Path, check: ReleaseAttestationCheck) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        check.command,
        cwd=bundle_root,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode == 0:
        return result
    if _is_transient_bundle_bootstrap_failure(result.stderr):
        _cleanup_runtime_artifacts(bundle_root)
        return subprocess.run(
            check.command,
            cwd=bundle_root,
            capture_output=True,
            text=True,
            check=False,
        )
    return result


def generate_release_attestation(
    bundle_root: Path,
    *,
    release_id: str,
    verifier_version: str,
    generated_at: str,
) -> dict[str, Any]:
    witness = resolve_release_attestation_witness()
    checks_payload: list[dict[str, Any]] = []
    try:
        for check in default_release_attestation_checks():
            result = _run_attestation_check(bundle_root, check)
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
            "Release attestation for the public verifier bundle. "
            "This proves bundle self-replay and transparency verification from the shipped bundle; "
            "the public reference release still defaults to synthetic trust roots unless environment-supplied release witnesses are configured."
        ),
    }
