"""State management for tracking processed offenses.

Uses SQLite to persist the high-water mark (last processed offense timestamp)
per SIEM connector. This ensures that after a restart, the service resumes
from where it left off without reprocessing old offenses.
"""

from __future__ import annotations

import logging
import os
import sqlite3
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS poll_state (
    siem_type TEXT PRIMARY KEY,
    last_poll_timestamp TEXT NOT NULL,
    last_offense_id TEXT,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS processed_offenses (
    siem_type TEXT NOT NULL,
    offense_id TEXT NOT NULL,
    misp_event_id TEXT,
    ioc_count INTEGER DEFAULT 0,
    processed_at TEXT NOT NULL,
    PRIMARY KEY (siem_type, offense_id)
);
"""


class StateManager:
    """SQLite-backed state manager for polling coordination."""

    def __init__(self, db_path: str, initial_lookback_hours: int = 24):
        self._db_path = db_path
        self._initial_lookback_hours = initial_lookback_hours
        self._ensure_db()

    def _ensure_db(self) -> None:
        """Create the database and tables if they don't exist."""
        os.makedirs(os.path.dirname(self._db_path) or ".", exist_ok=True)
        with self._connect() as conn:
            conn.executescript(_SCHEMA)
        logger.info("State database initialized at %s", self._db_path)

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self._db_path)

    def get_last_poll_timestamp(self, siem_type: str) -> datetime:
        """Get the last poll timestamp for a SIEM type.

        On first run (no state), returns current time minus initial_lookback_hours.
        """
        with self._connect() as conn:
            row = conn.execute(
                "SELECT last_poll_timestamp FROM poll_state WHERE siem_type = ?",
                (siem_type,),
            ).fetchone()

        if row:
            return datetime.fromisoformat(row[0])

        # First run: look back N hours
        default = datetime.now(timezone.utc) - timedelta(
            hours=self._initial_lookback_hours
        )
        logger.info(
            "No previous state for %s, using lookback of %d hours (since %s)",
            siem_type,
            self._initial_lookback_hours,
            default.isoformat(),
        )
        return default

    def update_last_poll_timestamp(
        self, siem_type: str, timestamp: datetime, last_offense_id: str | None = None
    ) -> None:
        """Update the high-water mark after a successful poll cycle."""
        now = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO poll_state (siem_type, last_poll_timestamp, last_offense_id, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(siem_type) DO UPDATE SET
                    last_poll_timestamp = excluded.last_poll_timestamp,
                    last_offense_id = excluded.last_offense_id,
                    updated_at = excluded.updated_at
                """,
                (siem_type, timestamp.isoformat(), last_offense_id, now),
            )
        logger.debug(
            "Updated poll state for %s: timestamp=%s, offense_id=%s",
            siem_type,
            timestamp.isoformat(),
            last_offense_id,
        )

    def is_offense_processed(self, siem_type: str, offense_id: str) -> bool:
        """Check if an offense has already been processed."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT 1 FROM processed_offenses WHERE siem_type = ? AND offense_id = ?",
                (siem_type, offense_id),
            ).fetchone()
        return row is not None

    def mark_offense_processed(
        self,
        siem_type: str,
        offense_id: str,
        misp_event_id: str | None = None,
        ioc_count: int = 0,
    ) -> None:
        """Record that an offense has been successfully processed."""
        now = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO processed_offenses
                    (siem_type, offense_id, misp_event_id, ioc_count, processed_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (siem_type, offense_id, misp_event_id, ioc_count, now),
            )
        logger.debug(
            "Marked offense %s:%s as processed (misp_event=%s, iocs=%d)",
            siem_type,
            offense_id,
            misp_event_id,
            ioc_count,
        )

    def get_stats(self, siem_type: str) -> dict:
        """Get processing statistics for a SIEM type."""
        with self._connect() as conn:
            total = conn.execute(
                "SELECT COUNT(*) FROM processed_offenses WHERE siem_type = ?",
                (siem_type,),
            ).fetchone()[0]
            total_iocs = conn.execute(
                "SELECT COALESCE(SUM(ioc_count), 0) FROM processed_offenses WHERE siem_type = ?",
                (siem_type,),
            ).fetchone()[0]
            last_ts = conn.execute(
                "SELECT last_poll_timestamp FROM poll_state WHERE siem_type = ?",
                (siem_type,),
            ).fetchone()

        return {
            "siem_type": siem_type,
            "total_offenses_processed": total,
            "total_iocs_pushed": total_iocs,
            "last_poll_timestamp": last_ts[0] if last_ts else None,
        }
