from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .artifacts import artifact_bytes_from_path, canonical_json_bytes, pretty_json_text, sha256_bytes


def _leaf_hash(entry: dict[str, Any]) -> str:
    return sha256_bytes(canonical_json_bytes(entry))


def _hash_pair(left: str, right: str) -> str:
    return sha256_bytes(f"{left}{right}".encode("utf-8"))


def merkle_root(leaf_hashes: list[str]) -> str:
    if not leaf_hashes:
        raise ValueError("cannot build a Merkle root for an empty leaf set")
    level = list(leaf_hashes)
    while len(level) > 1:
        next_level = []
        for index in range(0, len(level), 2):
            left = level[index]
            right = level[index + 1] if index + 1 < len(level) else left
            next_level.append(_hash_pair(left, right))
        level = next_level
    return level[0]


def inclusion_proof(leaf_hashes: list[str], leaf_index: int) -> list[dict[str, str]]:
    if leaf_index < 0 or leaf_index >= len(leaf_hashes):
        raise IndexError("leaf index out of range")

    proof: list[dict[str, str]] = []
    level = list(leaf_hashes)
    index = leaf_index
    while len(level) > 1:
        sibling_index = index - 1 if index % 2 else index + 1
        if sibling_index >= len(level):
            sibling_index = index
        position = "left" if sibling_index < index else "right"
        proof.append({
            "position": position,
            "hash": level[sibling_index],
        })

        next_level = []
        for offset in range(0, len(level), 2):
            left = level[offset]
            right = level[offset + 1] if offset + 1 < len(level) else left
            next_level.append(_hash_pair(left, right))
        level = next_level
        index //= 2
    return proof


def verify_inclusion_proof(leaf_hash: str, proof: list[dict[str, str]], expected_root: str) -> bool:
    current = leaf_hash
    for item in proof:
        if item["position"] == "left":
            current = _hash_pair(item["hash"], current)
        else:
            current = _hash_pair(current, item["hash"])
    return current == expected_root


def build_transparency_log(fixture_root: Path, generated_at: str) -> tuple[dict[str, Any], dict[str, Any]]:
    outcome_artifact = "certificate.json" if (fixture_root / "certificate.json").exists() else "punch-list.json"
    artifact_specs = [
        ("profile", "profile.json"),
        ("evidence_claims", "evidence-claims.json"),
        ("proof_bundle", "proof-bundle.json"),
        ("trust_surface_report", "trust-surface-report.md"),
        ("verification_result", "verification-result.json"),
        ("certificate" if outcome_artifact == "certificate.json" else "punch_list", outcome_artifact),
        ("replay_bundle", "replay-bundle.json"),
        ("witness_receipt", "witness-receipt.json"),
        ("revocation", "revocation.json"),
    ]

    entries = []
    for index, (artifact_type, relative_path) in enumerate(artifact_specs):
        artifact_path = fixture_root / relative_path
        artifact_digest = sha256_bytes(artifact_bytes_from_path(artifact_path))
        entry = {
            "index": index,
            "artifactType": artifact_type,
            "path": relative_path,
            "artifactSha256": artifact_digest,
        }
        entry["leafHash"] = _leaf_hash(entry)
        entries.append(entry)

    leaf_hashes = [entry["leafHash"] for entry in entries]
    root_hash = merkle_root(leaf_hashes)

    log = {
        "logId": f"{fixture_root.name}-transparency-log",
        "generatedAt": generated_at,
        "bundleId": json.loads((fixture_root / "proof-bundle.json").read_text())["bundleId"],
        "hashAlgorithm": "sha256",
        "rootHash": root_hash,
        "entries": entries,
    }
    proofs = {
        "bundleId": log["bundleId"],
        "rootHash": root_hash,
        "proofs": [
            {
                "path": entry["path"],
                "leafHash": entry["leafHash"],
                "proof": inclusion_proof(leaf_hashes, entry["index"]),
            }
            for entry in entries
        ],
    }
    return log, proofs


def transparency_log_text(log: dict[str, Any]) -> str:
    return pretty_json_text(log)


def inclusion_proofs_text(proofs: dict[str, Any]) -> str:
    return pretty_json_text(proofs)
