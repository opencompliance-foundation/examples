#!/usr/bin/env python3

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def _load_runtime():
    root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(root / "src"))
    from opencompliance.example_specs import FIXTURE_SPECS  # pylint: disable=import-error
    from opencompliance.verification_cli import execute_verify_cli  # pylint: disable=import-error

    return root, sorted(FIXTURE_SPECS), execute_verify_cli


def main() -> int:
    root, fixture_names, execute_verify_cli = _load_runtime()
    parser = argparse.ArgumentParser(description="Verify a synthetic OpenCompliance example fixture.")
    parser.add_argument("--fixture", choices=fixture_names, required=True)
    parser.add_argument(
        "--output-dir",
        help="Optional relative path to write or check generated artifacts against. Defaults to the selected fixture root.",
    )
    parser.add_argument("--write", action="store_true", help="Write generated artifacts back to the fixture directory.")
    parser.add_argument(
        "--check",
        action="store_true",
        help="Compare generated artifacts with the checked-in fixture files.",
    )
    parser.add_argument(
        "--print-classification",
        action="store_true",
        help="Print the classification records for the selected fixture.",
    )
    args = parser.parse_args()

    fixture_root = root / "fixtures" / "public" / args.fixture
    output_dir = (root / args.output_dir).resolve() if args.output_dir else fixture_root
    return execute_verify_cli(
        fixture_root,
        output_dir,
        write=args.write,
        check=args.check,
        print_classification=args.print_classification,
    )


if __name__ == "__main__":
    raise SystemExit(main())
