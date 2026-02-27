"""Shared test fixtures for MISP SIEM Integration tests."""

from __future__ import annotations

import os
import sys
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest

# Ensure src is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from core.models import IoC, IoCType, NormalizedOffense


@pytest.fixture
def sample_offense() -> NormalizedOffense:
    """A sample normalized offense with typical QRadar data."""
    return NormalizedOffense(
        offense_id="12345",
        siem_type="qradar",
        title="Excessive Firewall Denies from 203.0.113.50",
        description="Multiple firewall deny events detected from source 203.0.113.50 "
        "targeting internal servers. Associated domain: malware-c2.evil.com. "
        "Hash observed: d41d8cd98f00b204e9800998ecf8427e",
        severity=8,
        source_ip="203.0.113.50",
        destination_ip="10.0.0.5",
        timestamp=datetime(2026, 2, 27, 10, 30, 0, tzinfo=timezone.utc),
        raw_event={
            "id": 12345,
            "description": "Excessive Firewall Denies from 203.0.113.50",
            "offense_source": "203.0.113.50",
            "offense_type": 0,
            "source_address_ids": [101, 102],
            "local_destination_address_ids": [201],
            "magnitude": 8,
            "severity": 7,
            "status": "OPEN",
            "start_time": 1740646200000,
            "last_updated_time": 1740646200000,
            "categories": ["Firewall Deny", "Suspicious Activity"],
            "rules": [{"id": 100, "name": "Excessive Firewall Denies"}],
        },
        iocs=[
            IoC(type=IoCType.IP_SRC, value="203.0.113.50", comment="Source IP"),
            IoC(type=IoCType.DOMAIN, value="malware-c2.evil.com", comment="C2 domain"),
        ],
        categories=["Firewall Deny", "Suspicious Activity"],
        rules=["Excessive Firewall Denies"],
    )


@pytest.fixture
def sample_offense_no_iocs() -> NormalizedOffense:
    """A sample offense with no IoCs extracted yet."""
    return NormalizedOffense(
        offense_id="67890",
        siem_type="qradar",
        title="Login Failure",
        description="Multiple failed login attempts",
        severity=4,
        timestamp=datetime(2026, 2, 27, 11, 0, 0, tzinfo=timezone.utc),
        raw_event={"id": 67890, "magnitude": 4},
    )


@pytest.fixture
def mock_pymisp():
    """A mock PyMISP instance."""
    mock = MagicMock()
    mock.get_user.return_value = {
        "User": {"email": "siem@test.org", "org_id": "1"}
    }
    return mock


@pytest.fixture
def sample_qradar_offense_json() -> dict:
    """Raw QRadar API response for a single offense."""
    return {
        "id": 12345,
        "description": "Excessive Firewall Denies from 203.0.113.50",
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
        "categories": ["Firewall Deny"],
        "rules": [{"id": 100, "name": "Excessive Firewall Denies"}],
    }
