"""CLI entry point for the Hybrid Cybersecurity Threat Detection Platform."""

from __future__ import annotations

import argparse
import os
import sys


def _cmd_version(args: argparse.Namespace) -> None:  # noqa: ARG001
    """Print version information."""
    from src.common.config import get_config

    cfg = get_config()
    print("Threat Detection Platform")
    print(f"  Version  : {cfg.app_version}")
    print(f"  Env      : {cfg.app_env}")
    print(f"  Python   : {sys.version.split()[0]}")
    print(f"  Log level: {cfg.log_level}")
    print(f"  Log fmt  : {cfg.log_format}")


def _cmd_status(args: argparse.Namespace) -> None:  # noqa: ARG001
    """Print current configuration and component readiness."""
    from src.common.config import get_config
    from src.common.logging_setup import get_logger

    cfg = get_config()
    log = get_logger(__name__)
    log.info("status_check", version=cfg.app_version, env=cfg.app_env)

    print("\n=== Threat Detection Platform — Status ===\n")
    print(f"  App version     : {cfg.app_version}")
    print(f"  Environment     : {cfg.app_env}")
    print(f"  Log level       : {cfg.log_level}")
    print(f"  Database URL    : {cfg.database_url}")
    print(f"  Model dir       : {cfg.model_dir}")
    print(f"  Config dir      : {cfg.config_dir}")
    print()
    print("  Detection engines:")
    print(f"    Rules         : {'ENABLED' if cfg.rules_enabled else 'DISABLED'}")
    print(f"    ML            : {'ENABLED' if cfg.ml_enabled else 'DISABLED'}")
    print(f"    Behavioral    : {'ENABLED' if cfg.behavioral_enabled else 'DISABLED'}")
    print()
    print("  Component status:")
    print("    Phase 0: Foundation     : READY")
    print("    Phase 1: Ingestion      : READY (CSV, JSON, JSONL, Synthetic)")
    print("    Phase 2: Normalization  : READY (Parsers, Profiles, Canonical Schema)")
    print("    Phase 3: Features       : READY (Sliding Windows, Temporal, Flow)")
    print("    Phase 4: Rules engine   : NOT YET IMPLEMENTED")
    print("    Phase 5: Baselines      : NOT YET IMPLEMENTED")
    print("    Phase 6: ML engine      : NOT YET IMPLEMENTED")
    print("    Phase 7: Hybrid score   : NOT YET IMPLEMENTED")
    print("    Phase 8: Alerts         : NOT YET IMPLEMENTED")
    print()
    print("  Infrastructure  : READY")
    print("  Config loader   : READY")
    print("  Logging         : READY")
    print()


def _cmd_start(args: argparse.Namespace) -> None:  # noqa: ARG001
    """Start the FastAPI API server (available from Phase 14)."""
    print("API server not yet implemented — this will be available in Phase 14.")
    print("Run `python main.py status` to check current platform status.")
    sys.exit(1)


def build_parser() -> argparse.ArgumentParser:
    """Construct and return the top-level argument parser."""
    parser = argparse.ArgumentParser(
        prog="threat-detect",
        description=(
            "Hybrid Cybersecurity Threat Detection Platform — CLI\n\n"
            "An explainable threat detection platform combining rule-based detection, "
            "behavioral analytics, unsupervised anomaly detection, and event correlation."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default=None,
        help="Override the configured log level for this run.",
    )

    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")
    subparsers.required = True

    # version
    subparsers.add_parser("version", help="Print version and environment info.")

    # status
    subparsers.add_parser("status", help="Print configuration and component status.")

    # start
    start_parser = subparsers.add_parser("start", help="Start the API server (Phase 14+).")
    start_parser.add_argument("--host", default=None, help="Override API bind host.")
    start_parser.add_argument("--port", type=int, default=None, help="Override API port.")

    return parser


def cli_main() -> None:
    """Parse arguments, configure logging, dispatch to command handler."""
    parser = build_parser()
    args = parser.parse_args()

    # Allow --log-level flag to override env/config
    if args.log_level:
        os.environ["LOG_LEVEL"] = args.log_level

    # Configure logging before any command handler runs
    from src.common.config import get_config
    from src.common.logging_setup import configure_logging

    cfg = get_config()
    configure_logging(cfg)

    dispatch = {
        "version": _cmd_version,
        "status": _cmd_status,
        "start": _cmd_start,
    }
    dispatch[args.command](args)


if __name__ == "__main__":
    cli_main()
