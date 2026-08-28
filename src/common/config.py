"""Application configuration loader."""

from __future__ import annotations

import functools
from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class AppConfig(BaseSettings):
    """Central application configuration."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    app_env: Literal["development", "production", "test"] = Field(
        default="development",
        description="Runtime environment tag.",
    )
    app_version: str = Field(default="0.1.0", description="Semantic version string.")

    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = Field(
        default="INFO",
        description="Minimum log level to emit.",
    )
    log_format: Literal["json", "console"] = Field(
        default="console",
        description="'json' for machine-readable output; 'console' for human-readable.",
    )

    database_url: str = Field(
        default="sqlite:///./data/threat_detection.db",
        description="SQLAlchemy database connection URL.",
    )

    api_host: str = Field(default="0.0.0.0", description="Bind address for the API server.")
    api_port: int = Field(default=8000, ge=1, le=65535, description="TCP port for the API server.")
    api_reload: bool = Field(
        default=False,
        description="Enable uvicorn auto-reload.",
    )

    model_dir: Path = Field(
        default=Path("./models"),
        description="Directory for persisted model artifacts.",
    )
    config_dir: Path = Field(
        default=Path("./configs"),
        description="Directory for YAML detection/risk/model configs.",
    )
    data_dir: Path = Field(
        default=Path("./data"),
        description="Root data directory.",
    )

    model_version: str = Field(default="v1", description="Active model artifact version tag.")

    rules_enabled: bool = Field(default=True, description="Enable rule-based detection engine.")
    ml_enabled: bool = Field(default=True, description="Enable ML anomaly detection engine.")
    behavioral_enabled: bool = Field(
        default=True,
        description="Enable behavioral baseline engine.",
    )

    @field_validator("model_dir", "config_dir", "data_dir", mode="before")
    @classmethod
    def _coerce_path(cls, v: object) -> Path:
        return Path(str(v))



@functools.lru_cache(maxsize=1)
def get_config() -> AppConfig:
    """
    Return the singleton AppConfig instance.

    The instance is constructed once and cached for the lifetime of the
    process. Call `get_config.cache_clear()` in tests to force re-creation
    with a fresh environment.
    """
    return AppConfig()
