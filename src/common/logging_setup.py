"""
src/common/logging_setup.py
---------------------------
Structured logging initializer for the platform.

Uses `structlog` to provide:
  - JSON output in production / machine-readable mode
  - Human-readable colored output in development / console mode
  - Context binding so any module can attach fields (event_id, phase, etc.)
  - Integration with Python's stdlib `logging` so third-party libraries
    (FastAPI, SQLAlchemy, etc.) flow through the same pipeline

Usage
-----
    from src.common.logging_setup import get_logger, configure_logging
    from src.common.config import get_config

    configure_logging(get_config())          # call once at startup
    log = get_logger(__name__)
    log.info("platform_started", version="0.1.0")
    log = log.bind(phase="ingestion", source="csv")
    log.debug("record_loaded", record_count=42)
"""

from __future__ import annotations

import logging
import sys
from typing import TYPE_CHECKING, Any

import structlog

if TYPE_CHECKING:
    from src.common.config import AppConfig


def configure_logging(config: AppConfig) -> None:
    """
    Configure stdlib logging and structlog.

    Must be called once — typically in main.py before any other module
    emits log events.  Calling it multiple times is idempotent but
    redundant.

    Parameters
    ----------
    config:
        Loaded AppConfig; uses `log_level` and `log_format`.
    """
    log_level: int = getattr(logging, config.log_level, logging.INFO)

    # ------------------------------------------------------------------
    # Stdlib root logger — captures third-party library output
    # ------------------------------------------------------------------
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=log_level,
    )
    # Quiet down noisy libraries
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)

    # ------------------------------------------------------------------
    # Shared processors applied to every log event
    # ------------------------------------------------------------------
    shared_processors: list[Any] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        # Note: add_logger_name requires a stdlib-backed logger; we instead
        # rely on callers passing __name__ to get_logger() and binding it.
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
    ]

    if config.log_format == "json":
        # Machine-readable JSON — ideal for log aggregation pipelines
        processors: list[Any] = [
            *shared_processors,
            structlog.processors.dict_tracebacks,
            structlog.processors.JSONRenderer(),
        ]
    else:
        # Human-readable colored output for development
        processors = [
            *shared_processors,
            structlog.dev.ConsoleRenderer(colors=True),
        ]

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(log_level),
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str = __name__) -> structlog.BoundLogger:
    """
    Return a bound structlog logger for *name*.

    The returned logger supports `.bind(**kwargs)` to attach context
    that will appear in every subsequent log event from that logger
    instance without needing to pass it explicitly.

    Parameters
    ----------
    name:
        Typically `__name__` of the calling module.

    Returns
    -------
    structlog.BoundLogger
        A configured, ready-to-use logger.
    """
    return structlog.get_logger(name)
