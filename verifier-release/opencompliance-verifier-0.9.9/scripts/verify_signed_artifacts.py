#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def _load_runtime():
    root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(root / "src"))
    from opencompliance.signing import verify_signed_artifacts  # pylint: disable=import-error

    return root, verify_signed_artifacts


def main() -> int:
    root, verify_signed_artifacts = _load_runtime()
    parser = argparse.ArgumentParser(description="Verify a signed-artifact manifest against canonical OpenCompliance artifacts.")
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--artifact-root", required=True)
    parser.add_argument("--public-key")
    args = parser.parse_args()

    result = verify_signed_artifacts(
        manifest_path=(root / args.manifest).resolve(),
        artifact_root=(root / args.artifact_root).resolve(),
        public_key_path=(root / args.public_key).resolve() if args.public_key else None,
    )
    print(json.dumps(result, ensure_ascii=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
