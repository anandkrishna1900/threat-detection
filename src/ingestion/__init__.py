"""Data ingestion layer."""

from src.ingestion.base import DataSource, IngestionStats
from src.ingestion.csv_source import CSVSource
from src.ingestion.json_source import JSONLinesSource, JSONSource
from src.ingestion.models import SecurityEvent
from src.ingestion.synthetic_source import SyntheticSource

__all__ = [
    "DataSource",
    "IngestionStats",
    "CSVSource",
    "JSONSource",
    "JSONLinesSource",
    "SyntheticSource",
    "SecurityEvent",
]
