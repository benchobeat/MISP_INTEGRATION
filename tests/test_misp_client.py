"""Tests for the MISP client module."""

import os
import sys
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from core.misp_client import MISPClient
from core.models import IoC, IoCType, NormalizedOffense, ThreatLevel


@pytest.fixture
def misp_client():
    """Create a MISPClient with a mocked PyMISP backend."""
    with patch("core.misp_client.PyMISP") as MockPyMISP:
        mock_instance = MockPyMISP.return_value
        mock_instance.get_user.return_value = {
            "User": {"email": "siem@test.org", "org_id": "1"}
        }
        mock_instance.search.return_value = []

        client = MISPClient(
            url="https://misp.test.local",
            api_key="test_api_key",
            verify_ssl=False,
            distribution=0,
            tags=["tlp:amber", "automated:true"],
        )
        client._mock = mock_instance
        yield client


class TestMISPClientConnection:
    def test_connection_success(self, misp_client):
        assert misp_client.test_connection() is True

    def test_connection_failure(self, misp_client):
        misp_client._misp.get_user.side_effect = Exception("Connection refused")
        assert misp_client.test_connection() is False

    def test_connection_unexpected_response(self, misp_client):
        misp_client._misp.get_user.return_value = {"error": "unauthorized"}
        assert misp_client.test_connection() is False


class TestFindEventByOffense:
    def test_finds_existing_event(self, misp_client, sample_offense):
        mock_event = MagicMock()
        mock_event.id = 42
        misp_client._misp.search.return_value = [mock_event]

        result = misp_client.find_event_by_offense(sample_offense)
        assert result is not None
        assert result.id == 42

        # Verify it searched with the correct tag
        misp_client._misp.search.assert_called_once_with(
            controller="events",
            tags=["qradar:offense_id=12345"],
            limit=1,
            pythonify=True,
        )

    def test_no_existing_event(self, misp_client, sample_offense):
        misp_client._misp.search.return_value = []
        result = misp_client.find_event_by_offense(sample_offense)
        assert result is None


class TestCreateEventFromOffense:
    def test_creates_new_event(self, misp_client, sample_offense):
        """Should create a new MISP event when none exists."""
        mock_event = MagicMock()
        mock_event.id = 100
        mock_event.Attribute = []
        misp_client._misp.search.return_value = []  # No existing event
        misp_client._misp.add_event.return_value = mock_event

        result = misp_client.create_event_from_offense(sample_offense)

        assert result is not None
        assert result.id == 100
        misp_client._misp.add_event.assert_called_once()

        # Verify the event was constructed correctly
        call_args = misp_client._misp.add_event.call_args
        event = call_args[0][0]
        assert "[QRADAR]" in event.info
        assert "12345" in event.info

    def test_updates_existing_event(self, misp_client, sample_offense):
        """Should add new attributes when an event already exists."""
        existing_attr = MagicMock()
        existing_attr.value = "203.0.113.50"  # Already exists

        mock_existing_event = MagicMock()
        mock_existing_event.id = 42
        mock_existing_event.Attribute = [existing_attr]

        misp_client._misp.search.return_value = [mock_existing_event]

        result = misp_client.create_event_from_offense(sample_offense)
        assert result is not None

        # Should add the domain (new) but not the IP (already exists)
        add_attr_calls = misp_client._misp.add_attribute.call_args_list
        new_values = [
            call[0][1].value for call in add_attr_calls
            if len(call[0]) > 1 and hasattr(call[0][1], 'value')
        ]
        assert "malware-c2.evil.com" in new_values
        assert "203.0.113.50" not in new_values

    def test_no_iocs_returns_existing(self, misp_client, sample_offense_no_iocs):
        """Offense with no IoCs and existing event should return the event."""
        mock_event = MagicMock()
        mock_event.id = 42
        mock_event.Attribute = []
        misp_client._misp.search.return_value = [mock_event]

        result = misp_client.create_event_from_offense(sample_offense_no_iocs)
        # No add_event should be called since event exists
        misp_client._misp.add_event.assert_not_called()


class TestRetryLogic:
    def test_retries_on_failure(self, misp_client, sample_offense):
        """Should retry API calls on transient failures."""
        misp_client._misp.search.return_value = []

        # First call fails, second succeeds
        mock_event = MagicMock()
        mock_event.id = 1
        mock_event.Attribute = []
        misp_client._misp.add_event.side_effect = [
            Exception("Timeout"),
            mock_event,
        ]

        with patch("core.misp_client.time.sleep"):
            result = misp_client.create_event_from_offense(sample_offense)

        assert result is not None
        assert misp_client._misp.add_event.call_count == 2
