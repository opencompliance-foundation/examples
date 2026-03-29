from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def pretty_json_text(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, indent=2) + "\n"


def sha256_bytes(value: bytes) -> str:
    digest = hashlib.sha256()
    digest.update(value)
    return digest.hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def sha256_json(value: Any) -> str:
    return sha256_bytes(canonical_json_bytes(value))


def sha256_text(value: str) -> str:
    return sha256_bytes(value.encode("utf-8"))


def artifact_bytes_from_path(path: Path) -> bytes:
    if path.suffix == ".json":
        return canonical_json_bytes(json.loads(path.read_text()))
    return path.read_bytes()


def artifact_sha256_from_path(path: Path) -> str:
    return sha256_bytes(artifact_bytes_from_path(path))
