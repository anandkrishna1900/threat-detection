# Changelog

All notable changes to this project are documented here.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)  
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html)

---

## [Unreleased]

---

## [0.4.0] — 2026-08-28 — Phase 3: Feature Engineering

### Added
- `src/features/models.py` — `FeatureVector` schema with pure numerical/boolean cybersecurity features and dictionary/vector transformation methods (strictly leak-free).
- `src/features/state.py` — `EntityStateTracker` providing sliding-window (1m/5m/15m) behavioral state tracking per IP/user/host, unique destination diversity, and authentication failure burst monitoring.
- `src/features/extractors.py` — Temporal feature extractors (`hour_of_day`, `day_of_week`, `is_weekend`, `is_off_hours`) and flow metrics (`bytes_per_sec`, `bytes_ratio`, `bytes_total`).
- `src/features/pipeline.py` — `FeaturePipeline` orchestrating event-level and stream-level feature engineering and batch tabular dataset generation.
- `tests/unit/test_features.py` — 7 unit tests verifying temporal/flow extractors, sliding window metrics, burst flag triggers, and pipeline exports.


### Added
- `src/normalization/parsers.py` — Value parsers for timestamps (ISO 8601, UNIX epoch sec/msec/microsec, custom datetime formats to UTC), IP validation and port cleanup, port bounds validation (0-65535), protocol code/name mapping (IANA protocols), and numeric/string normalization.
- `src/normalization/field_mappings.py` — Canonical field alias dictionary covering heterogeneous schemas and pre-built dataset mapping profiles (`cic_ids`, `unsw_nb15`, `zeek_conn`).
- `src/normalization/normalizer.py` — `EventNormalizer` engine converting raw records/streams into canonical `SecurityEvent`s while preserving original `raw_data`.
- `tests/unit/test_normalization.py` — 12 unit tests covering all parser functions, alias resolution, mapping profiles, and stream normalization.


### Added
- `src/ingestion/models.py` — Canonical `SecurityEvent` Pydantic model with validation, ISO timestamp parsing, protocol uppercase normalization, and full raw_data preservation.
- `src/ingestion/base.py` — Abstract `DataSource` interface and `IngestionStats` metrics tracker (records read, yielded, skipped, and explicit error capture).
- `src/ingestion/csv_source.py` — `CSVSource` streaming reader with skip-and-log error handling for blank and malformed rows.
- `src/ingestion/json_source.py` — `JSONSource` (supporting single objects and object arrays) and `JSONLinesSource` for .jsonl files.
- `src/ingestion/synthetic_source.py` — `SyntheticSource` for in-memory and programmatic streams.
- `data/raw/` sample datasets: `sample_auth_events.csv`, `sample_network_events.json`, `sample_mixed_events.jsonl`.
- `tests/unit/test_ingestion.py` — 12 unit tests covering all source formats, stats metrics, error tracking, and model constraints.


### Added
- Full repository directory structure matching spec Section 6
  (`src/`, `tests/`, `scripts/`, `configs/`, `data/`, `docs/`,
  `models/`, `reports/`, `notebooks/`)
- `pyproject.toml` with full dependency list, Ruff, Black, mypy, and
  pytest configuration sections
- `requirements.txt` for pip-based installs
- `.env.example` with all supported environment variables documented
- `.gitignore` covering Python, venv, IDE, OS, data, and model artifacts
- `src/common/config.py` — pydantic-settings AppConfig with env-file
  support, typed fields, validators, and singleton `get_config()`
- `src/common/logging_setup.py` — structlog-based logger with JSON and
  console output modes; stdlib logging integration
- `main.py` — CLI entry point with `version`, `status`, and `start`
  subcommands (argparse)
- `configs/detection_rules.yaml` — 10 detection rule stubs (all disabled
  pending Phase 4 engine)
- `configs/model_config.yaml` — Isolation Forest parameters and
  preprocessing defaults (pending Phase 6)
- `configs/risk_config.yaml` — Risk weight defaults and severity
  thresholds (pending Phase 7)
- `tests/conftest.py` — shared fixtures: config cache isolation,
  minimal env setup
- `tests/unit/test_config.py` — 18 unit tests covering defaults, env
  overrides, singleton pattern, and validation errors
- `tests/unit/test_logging.py` — 9 unit tests covering configure_logging,
  get_logger, context binding, and level filtering
- `.github/workflows/ci.yml` — GitHub Actions CI: lint (Ruff), format
  check (Black), type check (mypy), pytest on Python 3.11 and 3.12
- `README.md` — project description, architecture diagram, quick start,
  example alert, phase status table, detection methodology, dataset
  disclaimer
- `CONTRIBUTING.md`, `SECURITY.md`, `LICENSE` (MIT), `docs/architecture.md`
- `data/README.md` — dataset usage guidelines

### Notes
- No detection logic is implemented in this phase.
- The system starts, configuration loads, and logging works.
- All 27 unit tests pass.
