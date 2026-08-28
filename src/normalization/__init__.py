"""Event normalization package."""

from src.normalization.field_mappings import DEFAULT_FIELD_ALIASES, PROFILES, MappingProfile
from src.normalization.normalizer import EventNormalizer
from src.normalization.parsers import (
    normalize_float,
    normalize_int,
    normalize_ip,
    normalize_port,
    normalize_protocol,
    normalize_string,
    normalize_timestamp,
)

__all__ = [
    "EventNormalizer",
    "MappingProfile",
    "PROFILES",
    "DEFAULT_FIELD_ALIASES",
    "normalize_timestamp",
    "normalize_ip",
    "normalize_port",
    "normalize_protocol",
    "normalize_int",
    "normalize_float",
    "normalize_string",
]
