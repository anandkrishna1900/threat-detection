# Contributing to the Threat Detection Platform

Thank you for your interest in contributing. Please read the following
guidelines before opening issues or pull requests.

## Code of Conduct

Be respectful and constructive in all interactions.

## Ethical / Legal Requirements (Non-Negotiable)

All contributions must:
- Use only public datasets, synthetic data, local lab environments, or
  systems you own or have explicit written permission to test.
- Never include real credentials, victim data, or sensitive logs.
- Never perform unauthorized scanning, exploitation, or credential attacks
  against real systems.
- Never introduce functionality designed for unauthorized access or offense.

## Development Setup

```bash
git clone https://github.com/your-username/threat-detection-platform.git
cd threat-detection-platform
python -m venv .venv
.venv\Scripts\activate   # Windows
# source .venv/bin/activate  # Linux/macOS
pip install -r requirements.txt
cp .env.example .env
pytest tests/ -v
```

## Workflow

1. Fork the repository.
2. Create a feature branch: `git checkout -b feature/phase-1-ingestion`
3. Write code with type hints throughout.
4. Write tests alongside code — not after.
5. Run the full test suite: `pytest tests/ -v`
6. Run the linter: `ruff check src/ tests/`
7. Run the formatter: `black src/ tests/`
8. Update CHANGELOG.md with a dated entry.
9. Open a pull request against `main`.

## Coding Standards

- Python 3.11+
- Type hints on all public functions and methods
- Structured logging (`get_logger(__name__)`) — no `print()` statements
  in production code
- Errors must be handled explicitly — no silent failures
- Configuration values must be externalised (YAML/env), not hardcoded
- Each module must have a docstring explaining its purpose

## Phase Discipline

Do not add code from a later phase before the current phase is tested
and documented. The phase checkpoints in the spec are hard gates.

## Commit Message Format

```
phase-N: short imperative description

Longer explanation if needed. Reference relevant spec section.
```

Example: `phase-1: add CSV data source with skip-and-log error handling`
