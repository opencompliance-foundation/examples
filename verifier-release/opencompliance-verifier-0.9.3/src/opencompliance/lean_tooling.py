from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
from functools import lru_cache
from pathlib import Path


LEAN_CACHE_ENV = "OPENCOMPLIANCE_LEAN_CACHE_DIR"
DISABLE_LEAN_CACHE_ENV = "OPENCOMPLIANCE_DISABLE_LEAN_CACHE"


def _required_build_artifact(lean_root: Path) -> Path:
    return lean_root / ".lake" / "build" / "lib" / "lean" / "OpenCompliance" / "Controls" / "Identity.olean"


def _lean_cache_enabled() -> bool:
    return os.environ.get(DISABLE_LEAN_CACHE_ENV, "").strip().lower() not in {"1", "true", "yes"}


def _lean_cache_base_dir() -> Path:
    configured = os.environ.get(LEAN_CACHE_ENV, "").strip()
    if configured:
        return Path(configured).expanduser().resolve()
    return (Path.home() / ".cache" / "opencompliance" / "lean").resolve()


def _cache_fingerprint_inputs(lean_root: Path) -> list[Path]:
    inputs = [
        lean_root / "lean-toolchain",
        lean_root / "lakefile.lean",
        lean_root / "OpenCompliance.lean",
    ]
    controls_root = lean_root / "OpenCompliance"
    if controls_root.exists():
        inputs.extend(sorted(path for path in controls_root.rglob("*.lean") if path.is_file()))
    return [path for path in inputs if path.exists()]


def _build_cache_key(lean_root: Path) -> str:
    digest = hashlib.sha256()
    for path in _cache_fingerprint_inputs(lean_root):
        digest.update(path.relative_to(lean_root).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def _build_cache_dir(lean_root: Path) -> Path:
    return _lean_cache_base_dir() / _build_cache_key(lean_root)


def _restore_cached_lake(lean_root: Path) -> bool:
    if not _lean_cache_enabled():
        return False
    cache_root = _build_cache_dir(lean_root)
    cache_lake_dir = cache_root / ".lake"
    if not _required_build_artifact(cache_root).exists() or not cache_lake_dir.exists():
        return False
    shutil.copytree(cache_lake_dir, lean_root / ".lake", dirs_exist_ok=True)
    return _required_build_artifact(lean_root).exists()


def _refresh_cached_lake(lean_root: Path) -> None:
    if not _lean_cache_enabled():
        return
    source_lake_dir = lean_root / ".lake"
    if not _required_build_artifact(lean_root).exists() or not source_lake_dir.exists():
        return

    cache_root = _build_cache_dir(lean_root)
    cache_root.parent.mkdir(parents=True, exist_ok=True)
    temp_root = cache_root.parent / (cache_root.name + ".tmp")
    if temp_root.exists():
        shutil.rmtree(temp_root)
    temp_root.mkdir(parents=True)
    shutil.copytree(source_lake_dir, temp_root / ".lake", dirs_exist_ok=True)
    if cache_root.exists():
        shutil.rmtree(cache_root)
    temp_root.rename(cache_root)


@lru_cache(maxsize=None)
def ensure_lean_package_ready(lean_root_raw: str) -> None:
    lean_root = Path(lean_root_raw).resolve()
    if _required_build_artifact(lean_root).exists():
        _refresh_cached_lake(lean_root)
        return
    if _restore_cached_lake(lean_root):
        return

    result = subprocess.run(
        ["lake", "build"],
        cwd=lean_root,
        capture_output=True,
        text=True,
        check=False,
        timeout=1800,
    )
    if result.returncode != 0:
        raise ValueError(
            "Lean package bootstrap failed:\n"
            f"ROOT: {lean_root}\n"
            f"STDOUT:\n{result.stdout}\n"
            f"STDERR:\n{result.stderr}"
        )
    _refresh_cached_lake(lean_root)
