"""Abstract base class for SIEM connectors.

All SIEM connectors (QRadar, FortiSIEM, RSA NetWitness, etc.) must
implement this interface. This ensures a consistent API for the
main polling loop regardless of the underlying SIEM.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Iterator

from core.models import NormalizedOffense


class BaseSIEMConnector(ABC):
    """Abstract interface for SIEM connectors."""

    @property
    @abstractmethod
    def siem_type(self) -> str:
        """Return the SIEM type identifier (e.g., 'qradar', 'fortisiem')."""

    @abstractmethod
    def test_connection(self) -> bool:
        """Verify connectivity and authentication to the SIEM.

        Returns True if the connection is successful, False otherwise.
        """

    @abstractmethod
    def fetch_offenses(self, since: datetime) -> Iterator[NormalizedOffense]:
        """Fetch offenses/alerts created or updated since a given timestamp.

        Args:
            since: Only return offenses updated after this timestamp.

        Yields:
            NormalizedOffense objects in chronological order.
        """

    @abstractmethod
    def get_offense_iocs(self, offense: NormalizedOffense) -> NormalizedOffense:
        """Enrich a normalized offense with extracted IoCs.

        Takes a basic NormalizedOffense (with metadata but no IoCs)
        and populates the iocs list by querying the SIEM for details
        (source/destination IPs, AQL queries, log payloads, etc.).

        Args:
            offense: The offense to enrich.

        Returns:
            The same offense with the iocs list populated.
        """
