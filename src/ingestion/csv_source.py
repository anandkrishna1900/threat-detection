"""CSV file data ingestion source."""

from __future__ import annotations

import csv
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from src.ingestion.base import DataSource


class CSVSource(DataSource):
    """Ingests security events from CSV files."""

    def __init__(self, file_path: str | Path, source_id: str | None = None) -> None:
        self.file_path = Path(file_path)
        super().__init__(source_id=source_id or f"csv:{self.file_path.name}")

    def read(self) -> Iterator[dict[str, Any]]:
        """Read CSV rows lazily and yield dictionary records."""
        if not self.file_path.exists():
            self.logger.error("csv_file_not_found", path=str(self.file_path))
            raise FileNotFoundError(f"CSV file not found: {self.file_path}")

        try:
            with open(self.file_path, "r", encoding="utf-8", errors="replace") as f:
                # Read all lines to track line counts explicitly
                lines = f.readlines()

            if not lines:
                self.logger.warning("csv_file_empty", path=str(self.file_path))
                return

            header_line = lines[0].strip()
            if not header_line:
                self.logger.warning("csv_empty_header", path=str(self.file_path))
                return

            header_reader = csv.reader([header_line])
            headers = [h.strip() for h in next(header_reader, []) if h is not None]
            if not headers:
                return

            for row_idx, line in enumerate(lines[1:], start=2):
                stripped_line = line.strip()
                if not stripped_line:
                    self.stats.record_failure(line, f"Line {row_idx}: Empty line")
                    self.logger.warning("csv_skip_blank_line", row=row_idx)
                    continue

                try:
                    row_values = next(csv.reader([stripped_line]))
                except Exception as exc:
                    self.stats.record_failure(stripped_line, f"Line {row_idx} parse error: {exc}")
                    self.logger.warning("csv_skip_parse_error", row=row_idx, error=str(exc))
                    continue

                if all(v.strip() == "" for v in row_values):
                    self.stats.record_failure(stripped_line, f"Line {row_idx}: All fields empty")
                    self.logger.warning("csv_skip_empty_fields", row=row_idx)
                    continue

                # Map to headers
                cleaned_row: dict[str, Any] = {}
                for i, h in enumerate(headers):
                    val = row_values[i].strip() if i < len(row_values) else ""
                    cleaned_row[h] = val

                self.stats.record_success()
                yield cleaned_row

        except Exception as exc:
            self.logger.error("csv_read_failed", path=str(self.file_path), error=str(exc))
            raise
