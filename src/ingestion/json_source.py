"""JSON and JSON Lines data ingestion sources."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from src.ingestion.base import DataSource


class JSONSource(DataSource):
    """Ingests security events from JSON files (array of objects or single object)."""

    def __init__(self, file_path: str | Path, source_id: str | None = None) -> None:
        self.file_path = Path(file_path)
        super().__init__(source_id=source_id or f"json:{self.file_path.name}")

    def read(self) -> Iterator[dict[str, Any]]:
        """Read JSON file and yield dictionary records."""
        if not self.file_path.exists():
            self.logger.error("json_file_not_found", path=str(self.file_path))
            raise FileNotFoundError(f"JSON file not found: {self.file_path}")

        with open(self.file_path, "r", encoding="utf-8") as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError as exc:
                self.stats.record_failure(str(self.file_path), f"JSON decode error: {exc}")
                self.logger.error("json_decode_error", path=str(self.file_path), error=str(exc))
                return

        if isinstance(data, list):
            for idx, item in enumerate(data):
                if isinstance(item, dict):
                    self.stats.record_success()
                    yield item
                else:
                    self.stats.record_failure(item, f"Item at index {idx} is not a JSON object")
                    self.logger.warning("json_skip_non_object", index=idx, item_type=type(item).__name__)
        elif isinstance(data, dict):
            self.stats.record_success()
            yield data
        else:
            self.stats.record_failure(data, f"Root JSON is neither a list nor an object: {type(data).__name__}")
            self.logger.warning("json_root_not_object_or_list", root_type=type(data).__name__)


class JSONLinesSource(DataSource):
    """Ingests security events from JSON Lines (.jsonl) files."""

    def __init__(self, file_path: str | Path, source_id: str | None = None) -> None:
        self.file_path = Path(file_path)
        super().__init__(source_id=source_id or f"jsonl:{self.file_path.name}")

    def read(self) -> Iterator[dict[str, Any]]:
        """Read JSON Lines file and yield dictionary records line by line."""
        if not self.file_path.exists():
            self.logger.error("jsonl_file_not_found", path=str(self.file_path))
            raise FileNotFoundError(f"JSON Lines file not found: {self.file_path}")

        with open(self.file_path, "r", encoding="utf-8", errors="replace") as f:
            for line_idx, line in enumerate(f, start=1):
                clean_line = line.strip()
                if not clean_line:
                    continue

                try:
                    record = json.loads(clean_line)
                    if isinstance(record, dict):
                        self.stats.record_success()
                        yield record
                    else:
                        self.stats.record_failure(clean_line, f"Line {line_idx} is not a JSON object")
                        self.logger.warning("jsonl_skip_non_object", line=line_idx)
                except json.JSONDecodeError as exc:
                    self.stats.record_failure(clean_line, f"Line {line_idx} invalid JSON: {exc}")
                    self.logger.warning("jsonl_skip_invalid_json", line=line_idx, error=str(exc))
