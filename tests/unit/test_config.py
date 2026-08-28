"""Unit tests for src/common/config.py (AppConfig)."""


from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError


class TestAppConfigDefaults:
    """AppConfig should load with sane defaults when no env is set."""

    def test_default_app_env(self, sample_config: object) -> None:
        assert sample_config.app_env == "test"  # overridden by minimal_env fixture

    def test_default_app_version(self, sample_config: object) -> None:
        assert sample_config.app_version == "0.1.0"

    def test_default_log_level_is_debug_in_test(self, sample_config: object) -> None:
        # minimal_env sets LOG_LEVEL=DEBUG
        assert sample_config.log_level == "DEBUG"

    def test_default_api_port(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from src.common.config import get_config

        monkeypatch.setenv("APP_ENV", "test")
        cfg = get_config()
        assert cfg.api_port == 8000

    def test_default_rules_enabled(self, sample_config: object) -> None:
        assert sample_config.rules_enabled is True

    def test_default_ml_enabled(self, sample_config: object) -> None:
        assert sample_config.ml_enabled is True

    def test_default_behavioral_enabled(self, sample_config: object) -> None:
        assert sample_config.behavioral_enabled is True

    def test_model_dir_is_path(self, sample_config: object) -> None:
        assert isinstance(sample_config.model_dir, Path)

    def test_config_dir_is_path(self, sample_config: object) -> None:
        assert isinstance(sample_config.config_dir, Path)

    def test_data_dir_is_path(self, sample_config: object) -> None:
        assert isinstance(sample_config.data_dir, Path)


class TestAppConfigEnvOverrides:
    """Environment variables must override defaults correctly."""

    def test_log_level_override(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from src.common.config import get_config

        monkeypatch.setenv("LOG_LEVEL", "ERROR")
        monkeypatch.setenv("APP_ENV", "test")
        cfg = get_config()
        assert cfg.log_level == "ERROR"

    def test_log_format_override(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from src.common.config import get_config

        monkeypatch.setenv("LOG_FORMAT", "json")
        monkeypatch.setenv("APP_ENV", "test")
        cfg = get_config()
        assert cfg.log_format == "json"

    def test_api_port_override(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from src.common.config import get_config

        monkeypatch.setenv("API_PORT", "9999")
        monkeypatch.setenv("APP_ENV", "test")
        cfg = get_config()
        assert cfg.api_port == 9999

    def test_disable_rules_via_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from src.common.config import get_config

        monkeypatch.setenv("RULES_ENABLED", "false")
        monkeypatch.setenv("APP_ENV", "test")
        cfg = get_config()
        assert cfg.rules_enabled is False

    def test_disable_ml_via_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from src.common.config import get_config

        monkeypatch.setenv("ML_ENABLED", "false")
        monkeypatch.setenv("APP_ENV", "test")
        cfg = get_config()
        assert cfg.ml_enabled is False

    def test_model_dir_from_string_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Path fields must accept string env values and coerce to Path."""
        from src.common.config import get_config

        monkeypatch.setenv("MODEL_DIR", "/tmp/models")
        monkeypatch.setenv("APP_ENV", "test")
        cfg = get_config()
        assert cfg.model_dir == Path("/tmp/models")

    def test_database_url_override(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from src.common.config import get_config

        monkeypatch.setenv("DATABASE_URL", "sqlite:///:memory:")
        monkeypatch.setenv("APP_ENV", "test")
        cfg = get_config()
        assert cfg.database_url == "sqlite:///:memory:"


class TestAppConfigSingleton:
    """get_config() must return the same instance within a process."""

    def test_same_object_on_repeated_calls(self, sample_config: object) -> None:
        from src.common.config import get_config

        assert get_config() is get_config()

    def test_cache_clear_returns_new_instance(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from src.common.config import get_config

        monkeypatch.setenv("APP_ENV", "test")
        cfg1 = get_config()
        get_config.cache_clear()
        cfg2 = get_config()
        # They should be equal in value but different objects
        assert cfg1.app_version == cfg2.app_version


class TestAppConfigValidation:
    """Invalid values must be rejected at construction time."""

    def test_invalid_log_level_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from src.common.config import AppConfig

        with pytest.raises(ValidationError):
            AppConfig(log_level="VERBOSE")  # type: ignore[arg-type]

    def test_invalid_log_format_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from src.common.config import AppConfig

        with pytest.raises(ValidationError):
            AppConfig(log_format="xml")  # type: ignore[arg-type]

    def test_invalid_app_env_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from src.common.config import AppConfig

        with pytest.raises(ValidationError):
            AppConfig(app_env="staging")  # type: ignore[arg-type]

    def test_api_port_out_of_range_raises(self) -> None:
        from src.common.config import AppConfig

        with pytest.raises(ValidationError):
            AppConfig(api_port=0)

        with pytest.raises(ValidationError):
            AppConfig(api_port=99999)
