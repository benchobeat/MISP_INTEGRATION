"""Main entry point for the MISP SIEM Integration polling service.

This module orchestrates the polling loop:
1. Reads configuration from YAML + environment variables
2. Initializes the SIEM connector, MISP client, and state manager
3. Runs an infinite loop that:
   - Fetches new offenses from the SIEM
   - Extracts IoCs from each offense
   - Creates/updates MISP events
   - Updates the polling state

Usage:
    python -m main                          # Run with default config
    CONFIG_PATH=./config/settings.yaml python -m main  # Custom config path
    python -m main --once                   # Run one cycle and exit
"""

from __future__ import annotations

import argparse
import logging
import os
import signal
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import yaml
from dotenv import load_dotenv

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).resolve().parent))

from connectors.qradar_connector import QRadarConnector
from core.misp_client import MISPClient
from core.state_manager import StateManager

logger = logging.getLogger("misp_integration")

# Graceful shutdown flag
_shutdown_requested = False


def _signal_handler(signum, frame):
    global _shutdown_requested
    logger.info("Shutdown signal received (%s), finishing current cycle...", signum)
    _shutdown_requested = True


def load_config(config_path: str | None = None) -> dict:
    """Load configuration from YAML file and environment variables.

    Environment variables override YAML values:
      - MISP_URL overrides misp.url
      - MISP_API_KEY (required, not in YAML)
      - QRADAR_URL overrides qradar.url
      - QRADAR_API_TOKEN (required, not in YAML)
      - CONFIG_PATH overrides default config file location
    """
    if not config_path:
        config_path = os.environ.get("CONFIG_PATH", "./config/settings.yaml")

    config_file = Path(config_path)
    if not config_file.exists():
        logger.error("Configuration file not found: %s", config_path)
        sys.exit(1)

    with open(config_file) as f:
        config = yaml.safe_load(f)

    # Override with environment variables
    if os.environ.get("MISP_URL"):
        config["misp"]["url"] = os.environ["MISP_URL"]
    if os.environ.get("QRADAR_URL"):
        config["qradar"]["url"] = os.environ["QRADAR_URL"]

    # Validate required secrets
    if not os.environ.get("MISP_API_KEY"):
        logger.error("MISP_API_KEY environment variable is required")
        sys.exit(1)
    if not os.environ.get("QRADAR_API_TOKEN"):
        logger.error("QRADAR_API_TOKEN environment variable is required")
        sys.exit(1)

    return config


def setup_logging(level: str = "INFO") -> None:
    """Configure structured logging."""
    log_format = (
        "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
    )
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format=log_format,
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=[
            logging.StreamHandler(sys.stdout),
        ],
    )


def create_components(config: dict) -> tuple[QRadarConnector, MISPClient, StateManager]:
    """Instantiate all components from configuration."""
    misp_cfg = config["misp"]
    qradar_cfg = config["qradar"]
    state_cfg = config["state"]
    general_cfg = config["general"]

    misp_client = MISPClient(
        url=misp_cfg["url"],
        api_key=os.environ["MISP_API_KEY"],
        verify_ssl=misp_cfg.get("verify_ssl", True),
        distribution=misp_cfg.get("distribution", 0),
        threat_level_default=misp_cfg.get("threat_level_default", 2),
        analysis_default=misp_cfg.get("analysis_default", 1),
        tags=misp_cfg.get("tags", []),
        publish=misp_cfg.get("publish", False),
    )

    qradar_connector = QRadarConnector(
        url=qradar_cfg["url"],
        api_token=os.environ["QRADAR_API_TOKEN"],
        verify_ssl=qradar_cfg.get("verify_ssl", True),
        api_version=qradar_cfg.get("api_version", "14.0"),
        offense_status_filter=qradar_cfg.get("offense_status_filter", "OPEN"),
        min_magnitude=qradar_cfg.get("min_magnitude", 1),
        offense_fields=qradar_cfg.get("offense_fields"),
    )

    state_manager = StateManager(
        db_path=state_cfg.get("path", "./data/state.db"),
        initial_lookback_hours=general_cfg.get("initial_lookback_hours", 24),
    )

    return qradar_connector, misp_client, state_manager


def run_poll_cycle(
    connector: QRadarConnector,
    misp_client: MISPClient,
    state: StateManager,
) -> dict:
    """Execute a single polling cycle.

    Returns a summary dict with counts of offenses processed, IoCs pushed, etc.
    """
    siem_type = connector.siem_type
    since = state.get_last_poll_timestamp(siem_type)
    cycle_start = datetime.now(timezone.utc)

    summary = {
        "offenses_fetched": 0,
        "offenses_new": 0,
        "offenses_skipped": 0,
        "offenses_failed": 0,
        "iocs_pushed": 0,
        "misp_events_created": 0,
    }

    logger.info("=== Poll cycle start (since: %s) ===", since.isoformat())

    latest_timestamp = since

    for offense in connector.fetch_offenses(since):
        summary["offenses_fetched"] += 1

        # Skip if already processed
        if state.is_offense_processed(siem_type, offense.offense_id):
            logger.debug("Offense %s already processed, skipping", offense.offense_id)
            summary["offenses_skipped"] += 1
            continue

        try:
            # Enrich with IoCs
            offense = connector.get_offense_iocs(offense)

            if not offense.iocs:
                logger.info(
                    "Offense %s has no IoCs to push, marking as processed",
                    offense.offense_id,
                )
                state.mark_offense_processed(siem_type, offense.offense_id, ioc_count=0)
                summary["offenses_new"] += 1
                continue

            # Push to MISP
            misp_event = misp_client.create_event_from_offense(offense)

            if misp_event:
                event_id = str(misp_event.id)
                ioc_count = len(offense.iocs)

                state.mark_offense_processed(
                    siem_type, offense.offense_id,
                    misp_event_id=event_id,
                    ioc_count=ioc_count,
                )
                summary["offenses_new"] += 1
                summary["iocs_pushed"] += ioc_count
                summary["misp_events_created"] += 1

                logger.info(
                    "Offense %s -> MISP event %s (%d IoCs)",
                    offense.offense_id,
                    event_id,
                    ioc_count,
                )
            else:
                summary["offenses_failed"] += 1
                logger.error(
                    "Failed to create MISP event for offense %s",
                    offense.offense_id,
                )

        except Exception:
            summary["offenses_failed"] += 1
            logger.exception(
                "Error processing offense %s", offense.offense_id
            )

        # Track the latest timestamp for the high-water mark
        if offense.timestamp > latest_timestamp:
            latest_timestamp = offense.timestamp

    # Update high-water mark
    if latest_timestamp > since:
        state.update_last_poll_timestamp(siem_type, latest_timestamp)

    logger.info(
        "=== Poll cycle complete: %d fetched, %d new, %d skipped, "
        "%d failed, %d IoCs pushed, %d MISP events ===",
        summary["offenses_fetched"],
        summary["offenses_new"],
        summary["offenses_skipped"],
        summary["offenses_failed"],
        summary["iocs_pushed"],
        summary["misp_events_created"],
    )

    return summary


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="MISP SIEM Integration - Polling Service"
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Run one poll cycle and exit (useful for cron jobs)",
    )
    parser.add_argument(
        "--config",
        type=str,
        default=None,
        help="Path to configuration YAML file",
    )
    parser.add_argument(
        "--stats",
        action="store_true",
        help="Print processing statistics and exit",
    )
    args = parser.parse_args()

    # Load environment variables from .env file
    load_dotenv()

    config = load_config(args.config)
    setup_logging(config.get("general", {}).get("log_level", "INFO"))

    logger.info("MISP SIEM Integration starting...")
    logger.info("Mode: %s", "single cycle" if args.once else "continuous polling")

    connector, misp_client, state = create_components(config)

    # Print stats and exit
    if args.stats:
        stats = state.get_stats(connector.siem_type)
        print(f"SIEM Type: {stats['siem_type']}")
        print(f"Total Offenses Processed: {stats['total_offenses_processed']}")
        print(f"Total IoCs Pushed: {stats['total_iocs_pushed']}")
        print(f"Last Poll: {stats['last_poll_timestamp'] or 'Never'}")
        return

    # Test connections
    logger.info("Testing connection to QRadar...")
    if not connector.test_connection():
        logger.error("Cannot connect to QRadar. Exiting.")
        sys.exit(1)

    logger.info("Testing connection to MISP...")
    if not misp_client.test_connection():
        logger.error("Cannot connect to MISP. Exiting.")
        sys.exit(1)

    logger.info("All connections verified successfully.")

    # Register signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    poll_interval = config.get("general", {}).get("polling_interval_seconds", 300)

    if args.once:
        run_poll_cycle(connector, misp_client, state)
        logger.info("Single cycle complete. Exiting.")
        return

    # Continuous polling loop
    logger.info("Starting continuous polling (interval: %ds)...", poll_interval)

    while not _shutdown_requested:
        try:
            run_poll_cycle(connector, misp_client, state)
        except Exception:
            logger.exception("Unexpected error in poll cycle")

        if _shutdown_requested:
            break

        logger.info("Sleeping %d seconds until next cycle...", poll_interval)

        # Sleep in small increments to allow quick shutdown
        for _ in range(poll_interval):
            if _shutdown_requested:
                break
            time.sleep(1)

    logger.info("MISP SIEM Integration stopped.")


if __name__ == "__main__":
    main()
