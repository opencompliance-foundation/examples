#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def _load_runtime():
    root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(root / "src"))
    from opencompliance.transparency import (  # pylint: disable=import-error
        merkle_root,
        verify_inclusion_proof,
    )

    return merkle_root, verify_inclusion_proof


def main() -> int:
    merkle_root, verify_inclusion_proof = _load_runtime()
    parser = argparse.ArgumentParser(description="Verify a synthetic OpenCompliance transparency log and proofs.")
    parser.add_argument("--log", required=True, help="Path to transparency-log.json")
    parser.add_argument("--proofs", required=True, help="Path to inclusion-proofs.json")
    args = parser.parse_args()

    log = json.loads(Path(args.log).read_text())
    proofs = json.loads(Path(args.proofs).read_text())

    leaf_hashes = [entry["leafHash"] for entry in log["entries"]]
    if merkle_root(leaf_hashes) != log["rootHash"]:
        raise SystemExit("root hash does not match the log entries")

    proofs_by_path = {item["path"]: item for item in proofs["proofs"]}
    for entry in log["entries"]:
        proof = proofs_by_path[entry["path"]]
        if proof["leafHash"] != entry["leafHash"]:
            raise SystemExit(f"leaf hash mismatch for {entry['path']}")
        if not verify_inclusion_proof(entry["leafHash"], proof["proof"], log["rootHash"]):
            raise SystemExit(f"inclusion proof failed for {entry['path']}")

    print(f"validated transparency log for bundle {log['bundleId']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

