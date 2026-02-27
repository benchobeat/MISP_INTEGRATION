"""Tests for the state manager module."""

import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from core.state_manager import StateManager


@pytest.fixture
def state_db(tmp_path):
    """Create a StateManager with a temporary database."""
    db_path = str(tmp_path / "test_state.db")
    return StateManager(db_path=db_path, initial_lookback_hours=24)


class TestStateManager:
    def test_initial_timestamp_uses_lookback(self, state_db):
        """First run should return now minus lookback hours."""
        ts = state_db.get_last_poll_timestamp("qradar")
        expected_min = datetime.now(timezone.utc) - timedelta(hours=25)
        expected_max = datetime.now(timezone.utc) - timedelta(hours=23)
        assert expected_min < ts < expected_max

    def test_update_and_get_timestamp(self, state_db):
        now = datetime(2026, 2, 27, 12, 0, 0, tzinfo=timezone.utc)
        state_db.update_last_poll_timestamp("qradar", now, "12345")

        retrieved = state_db.get_last_poll_timestamp("qradar")
        assert retrieved == now

    def test_update_overwrites_previous(self, state_db):
        t1 = datetime(2026, 2, 27, 10, 0, 0, tzinfo=timezone.utc)
        t2 = datetime(2026, 2, 27, 12, 0, 0, tzinfo=timezone.utc)

        state_db.update_last_poll_timestamp("qradar", t1)
        state_db.update_last_poll_timestamp("qradar", t2)

        assert state_db.get_last_poll_timestamp("qradar") == t2

    def test_separate_siem_types(self, state_db):
        t1 = datetime(2026, 2, 27, 10, 0, 0, tzinfo=timezone.utc)
        t2 = datetime(2026, 2, 27, 12, 0, 0, tzinfo=timezone.utc)

        state_db.update_last_poll_timestamp("qradar", t1)
        state_db.update_last_poll_timestamp("fortisiem", t2)

        assert state_db.get_last_poll_timestamp("qradar") == t1
        assert state_db.get_last_poll_timestamp("fortisiem") == t2

    def test_offense_not_processed_initially(self, state_db):
        assert state_db.is_offense_processed("qradar", "999") is False

    def test_mark_offense_processed(self, state_db):
        state_db.mark_offense_processed("qradar", "123", "evt_1", 5)
        assert state_db.is_offense_processed("qradar", "123") is True

    def test_offense_different_siem_not_confused(self, state_db):
        state_db.mark_offense_processed("qradar", "123")
        assert state_db.is_offense_processed("fortisiem", "123") is False

    def test_get_stats_empty(self, state_db):
        stats = state_db.get_stats("qradar")
        assert stats["total_offenses_processed"] == 0
        assert stats["total_iocs_pushed"] == 0
        assert stats["last_poll_timestamp"] is None

    def test_get_stats_with_data(self, state_db):
        t = datetime(2026, 2, 27, 10, 0, 0, tzinfo=timezone.utc)
        state_db.update_last_poll_timestamp("qradar", t)
        state_db.mark_offense_processed("qradar", "1", "evt_1", 3)
        state_db.mark_offense_processed("qradar", "2", "evt_2", 5)

        stats = state_db.get_stats("qradar")
        assert stats["total_offenses_processed"] == 2
        assert stats["total_iocs_pushed"] == 8
        assert stats["last_poll_timestamp"] is not None

    def test_creates_directory_if_missing(self, tmp_path):
        db_path = str(tmp_path / "nested" / "dir" / "state.db")
        sm = StateManager(db_path=db_path)
        # Should not raise
        sm.get_last_poll_timestamp("qradar")
