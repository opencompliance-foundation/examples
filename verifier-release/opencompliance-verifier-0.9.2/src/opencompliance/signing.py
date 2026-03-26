from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .artifacts import artifact_bytes_from_path, artifact_sha256_from_path


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text())


def _load_private_key(path: Path) -> Ed25519PrivateKey:
    return serialization.load_pem_private_key(path.read_bytes(), password=None)


def _load_public_key(path: Path) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(path.read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("expected an Ed25519 public key")
    return key


def _signature_entry(private_key: Ed25519PrivateKey, artifact_path: Path, relative_path: str) -> dict[str, str]:
    artifact_bytes = artifact_bytes_from_path(artifact_path)
    signature = private_key.sign(artifact_bytes)
    return {
        "path": relative_path,
        "sha256": artifact_sha256_from_path(artifact_path),
        "signature": base64.b64encode(signature).decode("ascii"),
    }


def sign_artifacts(
    artifact_root: Path,
    artifact_paths: list[str],
    private_key_path: Path,
    generated_at: str,
    bundle_id: str,
    signer: dict[str, str],
    note: str,
) -> dict[str, Any]:
    private_key = _load_private_key(private_key_path)
    signatures = [
        _signature_entry(private_key, artifact_root / relative_path, relative_path)
        for relative_path in artifact_paths
    ]
    return {
        "signatureBundleId": bundle_id,
        "generatedAt": generated_at,
        "signer": signer,
        "artifacts": signatures,
        "note": note,
    }


def verify_signed_artifacts(
    manifest_path: Path,
    artifact_root: Path,
    public_key_path: Path | None = None,
) -> dict[str, Any]:
    manifest = _load_json(manifest_path)
    signer = manifest["signer"]
    resolved_public_key_path = public_key_path or (manifest_path.parent / signer["publicKeyPath"])
    public_key = _load_public_key(resolved_public_key_path)

    verified_paths: list[str] = []
    for artifact in manifest["artifacts"]:
        artifact_path = artifact_root / artifact["path"]
        digest = artifact_sha256_from_path(artifact_path)
        if digest != artifact["sha256"]:
            raise ValueError(f"digest mismatch for {artifact['path']}")
        public_key.verify(
            base64.b64decode(artifact["signature"]),
            artifact_bytes_from_path(artifact_path),
        )
        verified_paths.append(artifact["path"])

    return {
        "signatureBundleId": manifest["signatureBundleId"],
        "status": "verified",
        "verifiedArtifactCount": len(verified_paths),
        "verifiedPaths": verified_paths,
        "signerKeyId": signer["keyId"],
        "signerType": signer["signerType"],
        "trustPolicyId": signer["trustPolicyId"],
    }
