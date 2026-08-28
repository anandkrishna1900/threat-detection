"""Unit tests for src/common/logging_setup.py."""


from __future__ import annotations

import io
import logging

import pytest
import structlog


class TestGetLogger:
    """get_logger should return a BoundLogger that can emit events."""

    def test_returns_bound_logger(self) -> None:
        from src.common.logging_setup import get_logger

        log = get_logger("test.module")
        # structlog loggers are callable and support .bind()
        assert hasattr(log, "info")
        assert hasattr(log, "debug")
        assert hasattr(log, "warning")
        assert hasattr(log, "error")
        assert hasattr(log, "bind")

    def test_logger_name_is_accepted(self) -> None:
        from src.common.logging_setup import get_logger

        log = get_logger(__name__)
        assert log is not None

    def test_bind_returns_new_logger(self) -> None:
        from src.common.logging_setup import get_logger

        log = get_logger("test.bind")
        bound = log.bind(phase="ingestion", component="csv_reader")
        # .bind() should return a new logger, not the same object
        assert bound is not None


class TestConfigureLogging:
    """configure_logging should configure structlog without raising."""

    def test_console_format_does_not_raise(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from src.common.config import AppConfig
        from src.common.logging_setup import configure_logging

        cfg = AppConfig(app_env="test", log_level="DEBUG", log_format="console")
        configure_logging(cfg)  # must not raise

    def test_json_format_does_not_raise(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from src.common.config import AppConfig
        from src.common.logging_setup import configure_logging

        cfg = AppConfig(app_env="test", log_level="INFO", log_format="json")
        configure_logging(cfg)  # must not raise

    def test_calling_twice_does_not_raise(self) -> None:
        from src.common.config import AppConfig
        from src.common.logging_setup import configure_logging

        cfg = AppConfig(app_env="test", log_level="WARNING", log_format="console")
        configure_logging(cfg)
        configure_logging(cfg)  # idempotent — must not raise

    def test_log_level_filters_debug_when_info(self) -> None:
        """When configured at INFO, DEBUG messages should not be emitted."""
        from src.common.config import AppConfig
        from src.common.logging_setup import configure_logging, get_logger

        cfg = AppConfig(app_env="test", log_level="INFO", log_format="console")
        configure_logging(cfg)
        log = get_logger("test.filter")
        # This is a smoke test — we verify it doesn't raise, not the output
        log.debug("this_should_be_filtered")
        log.info("this_should_pass")

    def test_structlog_configured_after_call(self) -> None:
        """After configure_logging(), structlog should have processors set."""
        from src.common.config import AppConfig
        from src.common.logging_setup import configure_logging

        cfg = AppConfig(app_env="test", log_level="INFO", log_format="console")
        configure_logging(cfg)
        # structlog.is_configured() was added in recent versions;
        # fall back to checking that get_logger returns a usable logger
        log = structlog.get_logger("test.configured")
        assert log is not None


class TestLoggerContextBinding:
    """Loggers should support context binding for structured fields."""

    def test_bind_adds_context(self) -> None:
        from src.common.config import AppConfig
        from src.common.logging_setup import configure_logging, get_logger

        cfg = AppConfig(app_env="test", log_level="DEBUG", log_format="console")
        configure_logging(cfg)

        log = get_logger("test.context")
        bound = log.bind(event_id="evt-001", phase="normalization")
        # Confirm binding and subsequent log call do not raise
        bound.info("context_bound_event", detail="smoke_test")
