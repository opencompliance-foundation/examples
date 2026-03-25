#!/usr/bin/env python3

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def _load_runtime():
    root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(root / "src"))
    from opencompliance.verification_cli import execute_verify_cli  # pylint: disable=import-error

    return root, execute_verify_cli


def main() -> int:
    root, execute_verify_cli = _load_runtime()
    parser = argparse.ArgumentParser(description="Verify an OpenCompliance fixture-shaped input root.")
    parser.add_argument("--fixture-root", required=True, help="Relative path to the fixture/input root.")
    parser.add_argument(
        "--output-dir",
        help="Optional relative path to write or check generated artifacts against. Defaults to the fixture root.",
    )
    parser.add_argument("--write", action="store_true", help="Write generated artifacts.")
    parser.add_argument("--check", action="store_true", help="Check generated artifacts against the output directory.")
    parser.add_argument("--print-classification", action="store_true", help="Print the classification records.")
    args = parser.parse_args()

    fixture_root = (root / args.fixture_root).resolve()
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
