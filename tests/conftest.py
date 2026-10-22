"""Shared fixtures.

Deliberately small: most tests construct their own objects so that a failure
points at the module under test rather than at a fixture.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


@pytest.fixture(scope="session")
def ca_factory():
    """Session-scoped CA creation.

    Generating a two-tier CA costs ~10ms, but several tests need one and none of
    them mutate it, so a factory with caching keeps the suite fast without
    sharing mutable revocation state.
    """
    from acme_rehearsal.ca import LocalCA

    cache = {}

    def _get(name: str = "default"):
        if name not in cache:
            cache[name] = LocalCA.create()
        return cache[name]

    return _get


@pytest.fixture
def sandbox(tmp_path: Path) -> Path:
    root = tmp_path / "sandbox"
    root.mkdir()
    return root
