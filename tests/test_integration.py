"""End-to-end integration tests with all components mocked.

These tests verify the full polling cycle: QRadar fetch → IoC extraction →
MISP event creation → state tracking.
"""

import os
import sys
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
import responses

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from connectors.qradar_connector import QRadarConnector
from core.misp_client import MISPClient
from core.state_manager import StateManager
from main import run_poll_cycle

QRADAR_URL = "https://qradar.test.local"


@pytest.fixture
def state_db(tmp_path):
    return StateManager(
        db_path=str(tmp_path / "test_state.db"),
        initial_lookback_hours=24,
    )


@pytest.fixture
def qradar_connector():
    return QRadarConnector(
        url=QRADAR_URL,
        api_token="test_token",
        verify_ssl=False,
        min_magnitude=1,
    )


@pytest.fixture
def misp_client():
    with patch("core.misp_client.PyMISP") as MockPyMISP:
        mock_instance = MockPyMISP.return_value
        mock_instance.get_user.return_value = {
            "User": {"email": "siem@test.org", "org_id": "1"}
        }
        mock_instance.search.return_value = []

        mock_event = MagicMock()
        mock_event.id = 100
        mock_event.Attribute = []
        mock_instance.add_event.return_value = mock_event

        client = MISPClient(
            url="https://misp.test.local",
            api_key="test_key",
            verify_ssl=False,
            tags=["tlp:amber", "automated:true"],
        )
        yield client


class TestFullPollCycle:
    @responses.activate
    def test_full_cycle_with_new_offenses(self, qradar_connector, misp_client, state_db):
        """Complete cycle: fetch offense → extract IoCs → create MISP event."""
        offense_data = {
            "id": 1001,
            "description": "C2 callback detected to 198.51.100.99",
            "offense_source": "198.51.100.99",
            "offense_type": 0,
            "source_address_ids": [],
            "local_destination_address_ids": [],
            "magnitude": 9,
            "severity": 8,
            "status": "OPEN",
            "start_time": 1740646200000,
            "last_updated_time": 1740646200000,
            "categories": ["Command and Control"],
            "rules": [{"id": 200, "name": "C2 Detection"}],
        }

        responses.add(
            responses.GET,
            f"{QRADAR_URL}/api/siem/offenses",
            json=[offense_data],
            status=200,
        )

        summary = run_poll_cycle(qradar_connector, misp_client, state_db)

        assert summary["offenses_fetched"] == 1
        assert summary["offenses_new"] == 1
        assert summary["offenses_failed"] == 0
        assert summary["misp_events_created"] == 1
        assert summary["iocs_pushed"] > 0

        # Verify state was updated
        assert state_db.is_offense_processed("qradar", "1001")

    @responses.activate
    def test_skips_already_processed(self, qradar_connector, misp_client, state_db):
        """Should skip offenses that were already processed."""
        # Pre-mark as processed
        state_db.mark_offense_processed("qradar", "1001", "evt_1", 3)

        offense_data = {
            "id": 1001,
            "description": "Already processed offense",
            "offense_source": "198.51.100.99",
            "offense_type": 0,
            "source_address_ids": [],
            "local_destination_address_ids": [],
            "magnitude": 5,
            "severity": 5,
            "status": "OPEN",
            "start_time": 1740646200000,
            "last_updated_time": 1740646200000,
            "categories": [],
            "rules": [],
        }

        responses.add(
            responses.GET,
            f"{QRADAR_URL}/api/siem/offenses",
            json=[offense_data],
            status=200,
        )

        summary = run_poll_cycle(qradar_connector, misp_client, state_db)

        assert summary["offenses_fetched"] == 1
        assert summary["offenses_skipped"] == 1
        assert summary["offenses_new"] == 0

    @responses.activate
    def test_no_offenses(self, qradar_connector, misp_client, state_db):
        """Should handle empty results gracefully."""
        responses.add(
            responses.GET,
            f"{QRADAR_URL}/api/siem/offenses",
            json=[],
            status=200,
        )

        summary = run_poll_cycle(qradar_connector, misp_client, state_db)

        assert summary["offenses_fetched"] == 0
        assert summary["offenses_new"] == 0

    @responses.activate
    def test_multiple_offenses(self, qradar_connector, misp_client, state_db):
        """Should process multiple offenses in a single cycle."""
        offenses = [
            {
                "id": i,
                "description": f"Offense {i} from 198.51.100.{i}",
                "offense_source": f"198.51.100.{i}",
                "offense_type": 0,
                "source_address_ids": [],
                "local_destination_address_ids": [],
                "magnitude": 7,
                "severity": 6,
                "status": "OPEN",
                "start_time": 1740646200000 + (i * 1000),
                "last_updated_time": 1740646200000 + (i * 1000),
                "categories": [],
                "rules": [],
            }
            for i in range(1, 4)
        ]

        responses.add(
            responses.GET,
            f"{QRADAR_URL}/api/siem/offenses",
            json=offenses,
            status=200,
        )

        summary = run_poll_cycle(qradar_connector, misp_client, state_db)

        assert summary["offenses_fetched"] == 3
        assert summary["offenses_new"] == 3

    @responses.activate
    def test_handles_misp_failure_gracefully(self, qradar_connector, misp_client, state_db):
        """Should continue processing other offenses if one fails."""
        offense_data = {
            "id": 2001,
            "description": "Will fail in MISP - 198.51.100.1",
            "offense_source": "198.51.100.1",
            "offense_type": 0,
            "source_address_ids": [],
            "local_destination_address_ids": [],
            "magnitude": 6,
            "severity": 5,
            "status": "OPEN",
            "start_time": 1740646200000,
            "last_updated_time": 1740646200000,
            "categories": [],
            "rules": [],
        }

        responses.add(
            responses.GET,
            f"{QRADAR_URL}/api/siem/offenses",
            json=[offense_data],
            status=200,
        )

        # Make MISP fail
        misp_client._misp.add_event.return_value = None

        summary = run_poll_cycle(qradar_connector, misp_client, state_db)

        # Should record the failure but not crash
        assert summary["offenses_fetched"] == 1
        assert summary["offenses_failed"] == 1
