"""Tests for the QRadar connector module."""

import os
import sys
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
import responses

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from connectors.qradar_connector import QRadarConnector
from core.models import IoCType

QRADAR_URL = "https://qradar.test.local"


@pytest.fixture
def connector():
    """Create a QRadar connector for testing."""
    return QRadarConnector(
        url=QRADAR_URL,
        api_token="test_token",
        verify_ssl=False,
        min_magnitude=1,
    )


@pytest.fixture
def mock_offense():
    """A raw QRadar offense response."""
    return {
        "id": 12345,
        "description": "Malicious activity from 203.0.113.50 to evil.com",
        "offense_source": "203.0.113.50",
        "offense_type": 0,
        "source_address_ids": [101],
        "local_destination_address_ids": [201],
        "magnitude": 8,
        "severity": 7,
        "relevance": 5,
        "credibility": 5,
        "status": "OPEN",
        "start_time": 1740646200000,
        "last_updated_time": 1740646200000,
        "categories": ["Suspicious Activity"],
        "rules": [{"id": 100, "name": "Test Rule"}],
    }


class TestQRadarConnectorProperties:
    def test_siem_type(self, connector):
        assert connector.siem_type == "qradar"


class TestTestConnection:
    @responses.activate
    def test_success(self, connector):
        responses.add(
            responses.GET,
            f"{QRADAR_URL}/api/system/about",
            json={"external_version": "7.5.0"},
            status=200,
        )
        assert connector.test_connection() is True

    @responses.activate
    def test_failure(self, connector):
        responses.add(
            responses.GET,
            f"{QRADAR_URL}/api/system/about",
            json={"error": "unauthorized"},
            status=401,
        )
        assert connector.test_connection() is False


class TestFetchOffenses:
    @responses.activate
    def test_fetches_offenses(self, connector, mock_offense):
        responses.add(
            responses.GET,
            f"{QRADAR_URL}/api/siem/offenses",
            json=[mock_offense],
            status=200,
        )

        since = datetime(2026, 2, 27, 0, 0, 0, tzinfo=timezone.utc)
        offenses = list(connector.fetch_offenses(since))

        assert len(offenses) == 1
        assert offenses[0].offense_id == "12345"
        assert offenses[0].siem_type == "qradar"
        assert offenses[0].severity == 8  # magnitude

    @responses.activate
    def test_empty_result(self, connector):
        responses.add(
            responses.GET,
            f"{QRADAR_URL}/api/siem/offenses",
            json=[],
            status=200,
        )

        since = datetime(2026, 2, 27, 0, 0, 0, tzinfo=timezone.utc)
        offenses = list(connector.fetch_offenses(since))
        assert len(offenses) == 0

    @responses.activate
    def test_offense_normalization(self, connector, mock_offense):
        responses.add(
            responses.GET,
            f"{QRADAR_URL}/api/siem/offenses",
            json=[mock_offense],
            status=200,
        )

        since = datetime(2026, 2, 27, 0, 0, 0, tzinfo=timezone.utc)
        offense = list(connector.fetch_offenses(since))[0]

        assert offense.title == mock_offense["description"]
        assert offense.categories == ["Suspicious Activity"]
        assert offense.rules == ["Test Rule"]
        assert offense.raw_event == mock_offense


class TestGetOffenseIocs:
    @responses.activate
    def test_resolves_ips_and_extracts_iocs(self, connector, mock_offense):
        # Mock offense fetch
        responses.add(
            responses.GET,
            f"{QRADAR_URL}/api/siem/offenses",
            json=[mock_offense],
            status=200,
        )
        # Mock source address resolution
        responses.add(
            responses.GET,
            f"{QRADAR_URL}/api/siem/source_addresses/101",
            json={"source_ip": "203.0.113.50"},
            status=200,
        )
        # Mock destination address resolution
        responses.add(
            responses.GET,
            f"{QRADAR_URL}/api/siem/local_destination_addresses/201",
            json={"local_destination_ip": "198.51.100.10"},
            status=200,
        )

        since = datetime(2026, 2, 27, 0, 0, 0, tzinfo=timezone.utc)
        offense = list(connector.fetch_offenses(since))[0]
        enriched = connector.get_offense_iocs(offense)

        assert len(enriched.iocs) > 0

        ioc_types = {ioc.type for ioc in enriched.iocs}
        ioc_values = {ioc.value for ioc in enriched.iocs}

        # Should have source and destination IPs
        assert IoCType.IP_SRC in ioc_types
        assert IoCType.IP_DST in ioc_types
        assert "203.0.113.50" in ioc_values
        assert "198.51.100.10" in ioc_values

    @responses.activate
    def test_deduplicates_iocs(self, connector, mock_offense):
        """offense_source is same IP as resolved source - should deduplicate."""
        responses.add(
            responses.GET,
            f"{QRADAR_URL}/api/siem/offenses",
            json=[mock_offense],
            status=200,
        )
        responses.add(
            responses.GET,
            f"{QRADAR_URL}/api/siem/source_addresses/101",
            json={"source_ip": "203.0.113.50"},  # Same as offense_source
            status=200,
        )
        responses.add(
            responses.GET,
            f"{QRADAR_URL}/api/siem/local_destination_addresses/201",
            json={"local_destination_ip": "198.51.100.10"},
            status=200,
        )

        since = datetime(2026, 2, 27, 0, 0, 0, tzinfo=timezone.utc)
        offense = list(connector.fetch_offenses(since))[0]
        enriched = connector.get_offense_iocs(offense)

        # Count how many times 203.0.113.50 appears as ip-src
        ip_src_count = sum(
            1 for ioc in enriched.iocs
            if ioc.value == "203.0.113.50" and ioc.type == IoCType.IP_SRC
        )
        assert ip_src_count == 1  # Should be deduplicated

    @responses.activate
    def test_handles_address_resolution_failure(self, connector, mock_offense):
        """Should continue even if IP resolution fails."""
        responses.add(
            responses.GET,
            f"{QRADAR_URL}/api/siem/offenses",
            json=[mock_offense],
            status=200,
        )
        # Source address fails
        responses.add(
            responses.GET,
            f"{QRADAR_URL}/api/siem/source_addresses/101",
            json={"error": "not found"},
            status=404,
        )
        responses.add(
            responses.GET,
            f"{QRADAR_URL}/api/siem/local_destination_addresses/201",
            json={"error": "not found"},
            status=404,
        )

        since = datetime(2026, 2, 27, 0, 0, 0, tzinfo=timezone.utc)
        offense = list(connector.fetch_offenses(since))[0]

        # Should not raise
        enriched = connector.get_offense_iocs(offense)
        # Should still have IoCs from offense_source and description
        assert len(enriched.iocs) > 0
