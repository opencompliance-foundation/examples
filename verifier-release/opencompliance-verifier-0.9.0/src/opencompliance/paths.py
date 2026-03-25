from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path
from typing import Iterator


_REPO_ROOT_OVERRIDE: ContextVar[Path | None] = ContextVar("opencompliance_repo_root", default=None)


def _candidate_roots(start: Path | None) -> list[Path]:
    if start is None:
        current = Path(__file__).resolve().parent
    else:
        current = start.resolve()
        if current.is_file():
            current = current.parent
    return [current, *current.parents]


def find_repo_root(start: Path | None = None) -> Path:
    override = _REPO_ROOT_OVERRIDE.get()
    if override is not None:
        return override

    for candidate in _candidate_roots(start):
        if (candidate / "open-specs" / "control-boundaries.json").exists() and (
            candidate / "lean4-controls"
        ).exists():
            return candidate

    raise FileNotFoundError(f"Could not locate the OpenCompliance repo root from {start!r}")


@contextmanager
def override_repo_root(repo_root: Path) -> Iterator[None]:
    token = _REPO_ROOT_OVERRIDE.set(repo_root.resolve())
    try:
        yield
    finally:
        _REPO_ROOT_OVERRIDE.reset(token)
