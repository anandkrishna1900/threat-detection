"""
tests/conftest.py
-----------------
Shared pytest fixtures for the Threat Detection Platform test suite.

Fixtures defined here are available to all test modules without
explicit imports — pytest discovers them automatically.
"""

from __future__ import annotations

from collections.abc import Generator
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from src.common.config import AppConfig


@pytest.fixture(autouse=True)
def isolate_config() -> Generator[None, None, None]:
    """
    Ensure each test starts with a fresh AppConfig instance.

    AppConfig is cached via lru_cache; this fixture clears the cache
    before and after every test so that environment mutations made
    inside one test do not leak into another.
    """
    from src.common.config import get_config

    get_config.cache_clear()
    yield
    get_config.cache_clear()


@pytest.fixture()
def minimal_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Set the bare-minimum environment variables for a valid config.

    Useful as a baseline that other fixtures can extend.
    """
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("LOG_LEVEL", "DEBUG")
    monkeypatch.setenv("LOG_FORMAT", "console")


@pytest.fixture()
def sample_config(minimal_env: None) -> AppConfig:
    """Return a freshly-constructed AppConfig in test mode."""
    from src.common.config import get_config

    return get_config()
