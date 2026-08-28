"""Abstract base class and stats tracking for data ingestion sources."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

from src.common.logging_setup import get_logger

logger = get_logger(__name__)


@dataclass
class IngestionStats:
    """Tracks metrics and errors for an ingestion run."""

    records_read: int = 0
    records_yielded: int = 0
    records_skipped: int = 0
    errors: list[dict[str, Any]] = field(default_factory=list)

    def record_success(self) -> None:
        self.records_read += 1
        self.records_yielded += 1

    def record_failure(self, raw_record: Any, reason: str) -> None:
        self.records_read += 1
        self.records_skipped += 1
        self.errors.append({"raw": str(raw_record), "reason": reason})


class DataSource(ABC):
    """Abstract base class for all data ingestion sources."""

    def __init__(self, source_id: str) -> None:
        self.source_id = source_id
        self.stats = IngestionStats()
        self.logger = get_logger(f"{__name__}.{self.__class__.__name__}")

    @abstractmethod
    def read(self) -> Iterator[dict[str, Any]]:
        """
        Yield raw dictionary records from the underlying source.
        Malformed records are skipped, counted, and logged.
        """
        pass

    def get_stats(self) -> IngestionStats:
        """Return ingestion statistics."""
        return self.stats

    def reset_stats(self) -> None:
        """Reset statistics for a new run."""
        self.stats = IngestionStats()
