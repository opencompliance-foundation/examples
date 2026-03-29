#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def _load_runtime():
    root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(root / "src"))
    from opencompliance.example_specs import FIXTURE_SPECS  # pylint: disable=import-error
    from opencompliance.proof_runner import run_lean_batch  # pylint: disable=import-error
    from opencompliance.verifier import generate_proof_bundle  # pylint: disable=import-error

    return root, sorted(FIXTURE_SPECS), generate_proof_bundle, run_lean_batch


def main() -> int:
    root, fixture_names, generate_proof_bundle, run_lean_batch = _load_runtime()
    parser = argparse.ArgumentParser(description="Run the private Lean proof batch for a synthetic OpenCompliance fixture.")
    parser.add_argument("--fixture", choices=fixture_names, required=True)
    args = parser.parse_args()

    fixture_root = root / "fixtures" / "public" / args.fixture
    proof_bundle = generate_proof_bundle(fixture_root)
    result = proof_bundle.get("proofRunner") or run_lean_batch(fixture_root, proof_bundle)
    print(json.dumps(result, ensure_ascii=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
