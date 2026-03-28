#!/usr/bin/env python3

from __future__ import annotations

import argparse
import difflib
import json
import sys
from pathlib import Path


def _load_runtime():
    root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(root / "src"))
    from opencompliance.artifacts import pretty_json_text  # pylint: disable=import-error
    from opencompliance.release import (  # pylint: disable=import-error
        PUBLIC_VERIFIER_RELEASE_ID,
        PUBLIC_VERIFIER_VERSION,
        PUBLIC_VERIFIER_RELEASED_AT,
    )
    from opencompliance.release_attestation import generate_release_attestation  # pylint: disable=import-error

    return {
        "root": root,
        "pretty_json_text": pretty_json_text,
        "release_id": PUBLIC_VERIFIER_RELEASE_ID,
        "verifier_version": PUBLIC_VERIFIER_VERSION,
        "released_at": PUBLIC_VERIFIER_RELEASED_AT,
        "generate_release_attestation": generate_release_attestation,
    }


def main() -> int:
    runtime = _load_runtime()
    root: Path = runtime["root"]
    pretty_json_text = runtime["pretty_json_text"]
    generate_release_attestation = runtime["generate_release_attestation"]

    parser = argparse.ArgumentParser(description="Generate or check the OpenCompliance public verifier release attestation.")
    parser.add_argument(
        "--bundle-root",
        default=".",
        help="Path to the verifier release bundle root.",
    )
    parser.add_argument("--write", action="store_true", help="Write release-attestation.json into the bundle root.")
    parser.add_argument("--check", action="store_true", help="Check the generated attestation against the checked-in file.")
    args = parser.parse_args()

    if not args.write and not args.check:
        raise SystemExit("pass --write or --check")

    bundle_root = (root / args.bundle_root).resolve()
    target = bundle_root / "release-attestation.json"
    payload = generate_release_attestation(
        bundle_root,
        release_id=runtime["release_id"],
        verifier_version=runtime["verifier_version"],
        generated_at=runtime["released_at"],
    )
    text = pretty_json_text(payload)

    if args.check:
        if not target.exists():
            print(f"missing expected artifact: {target}")
            return 1
        existing = target.read_text(encoding="utf-8")
        if existing != text:
            diff = "".join(
                difflib.unified_diff(
                    existing.splitlines(keepends=True),
                    text.splitlines(keepends=True),
                    fromfile=str(target),
                    tofile=f"generated:{target.name}",
                )
            )
            print(diff, end="")
            return 1

    if args.write:
        target.write_text(text, encoding="utf-8")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
