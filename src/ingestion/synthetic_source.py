"""In-memory and synthetic data ingestion source."""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from typing import Any

from src.ingestion.base import DataSource


class SyntheticSource(DataSource):
    """Yields records from an in-memory iterable or generator."""

    def __init__(self, records: Iterable[dict[str, Any]], source_id: str = "synthetic:in_memory") -> None:
        super().__init__(source_id=source_id)
        self.records = records

    def read(self) -> Iterator[dict[str, Any]]:
        """Yield records from the provided iterable."""
        for idx, record in enumerate(self.records):
            if not isinstance(record, dict):
                self.stats.record_failure(record, f"Record at index {idx} is not a dictionary")
                self.logger.warning("synthetic_skip_non_dict", index=idx)
                continue
            self.stats.record_success()
            yield record
