from __future__ import annotations

import subprocess
from functools import lru_cache
from pathlib import Path


def _required_build_artifact(lean_root: Path) -> Path:
    return lean_root / ".lake" / "build" / "lib" / "lean" / "OpenCompliance" / "Controls" / "Identity.olean"


@lru_cache(maxsize=None)
def ensure_lean_package_ready(lean_root_raw: str) -> None:
    lean_root = Path(lean_root_raw).resolve()
    if _required_build_artifact(lean_root).exists():
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
