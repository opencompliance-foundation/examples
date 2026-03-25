from __future__ import annotations

import difflib
from pathlib import Path

from .transparency import build_transparency_log, inclusion_proofs_text, transparency_log_text
from .verification_api import run_verify
from .verifier import classify_fixture, validate_oscal_linkage


TRANSPARENCY_GENERATED_AT = "2026-03-24T22:00:00Z"
SOURCE_BUNDLE_INPUTS = ("profile.json", "evidence-claims.json")


def _check_or_write_artifact(path: Path, content: str, *, check: bool, write: bool) -> int:
    if check:
        if not path.exists():
            print(f"missing expected artifact: {path}")
            return 1
        existing = path.read_text()
        if existing != content:
            diff = "".join(
                difflib.unified_diff(
                    existing.splitlines(keepends=True),
                    content.splitlines(keepends=True),
                    fromfile=str(path),
                    tofile=f"generated:{path.name}",
                )
            )
            print(diff, end="")
            return 1
    if write:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    return 0


def execute_verify_cli(
    fixture_root: Path,
    output_root: Path | None = None,
    *,
    write: bool = False,
    check: bool = False,
    print_classification: bool = False,
) -> int:
    output_dir = output_root or fixture_root
    validate_oscal_linkage(fixture_root)
    generated = run_verify(fixture_root)

    if print_classification:
        for record in classify_fixture(fixture_root):
            print(f"{record.claim_id} {record.route} {record.control_refs} :: {record.rationale}")

    if check or write:
        for name in SOURCE_BUNDLE_INPUTS:
            source_path = fixture_root / name
            if not source_path.exists():
                continue
            result = _check_or_write_artifact(
                output_dir / name,
                source_path.read_text(),
                check=check,
                write=write,
            )
            if result != 0:
                return result

    for name, content in generated.items():
        if name == "fixture":
            continue
        path = output_dir / name
        result = _check_or_write_artifact(path, content, check=check, write=write)
        if result != 0:
            return result

    if check or write:
        log, proofs = build_transparency_log(output_dir, TRANSPARENCY_GENERATED_AT)
        transparency_artifacts = {
            output_dir / "transparency-log.json": transparency_log_text(log),
            output_dir / "inclusion-proofs.json": inclusion_proofs_text(proofs),
        }
        for path, content in transparency_artifacts.items():
            result = _check_or_write_artifact(path, content, check=check, write=write)
            if result != 0:
                return result

    return 0
