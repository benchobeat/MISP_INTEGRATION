"""IBM QRadar SIEM connector.

Implements the BaseSIEMConnector interface for IBM QRadar. Uses the
QRadar REST API to fetch offenses, resolve IP addresses, and extract
IoCs from offense data and associated events via AQL queries.

QRadar API Reference:
- Offenses: GET /api/siem/offenses
- Source addresses: GET /api/siem/source_addresses/{id}
- Local dest addresses: GET /api/siem/local_destination_addresses/{id}
- AQL searches: POST /api/ariel/searches
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Any, Iterator

import requests

from connectors.base_connector import BaseSIEMConnector
from core.ioc_extractor import extract_iocs_from_text
from core.ioc_mapper import map_offense_source, map_qradar_destination_ip, map_qradar_source_ip
from core.models import IoC, IoCType, NormalizedOffense

logger = logging.getLogger(__name__)

# QRadar API timestamps are in milliseconds since epoch
_MS_TO_SEC = 1000


class QRadarConnector(BaseSIEMConnector):
    """QRadar REST API connector for fetching offenses and extracting IoCs."""

    def __init__(
        self,
        url: str,
        api_token: str,
        verify_ssl: bool = True,
        api_version: str = "14.0",
        offense_status_filter: str = "OPEN",
        min_magnitude: int = 1,
        offense_fields: list[str] | None = None,
    ):
        self._base_url = url.rstrip("/")
        self._api_token = api_token
        self._verify_ssl = verify_ssl
        self._api_version = api_version
        self._offense_status_filter = offense_status_filter
        self._min_magnitude = min_magnitude
        self._offense_fields = offense_fields or [
            "id", "description", "offense_source", "offense_type",
            "source_address_ids", "local_destination_address_ids",
            "magnitude", "severity", "relevance", "credibility",
            "status", "start_time", "last_updated_time",
            "categories", "rules",
        ]

        self._session = requests.Session()
        self._session.headers.update({
            "SEC": self._api_token,
            "Accept": "application/json",
            "Version": self._api_version,
        })
        self._session.verify = self._verify_ssl

    @property
    def siem_type(self) -> str:
        return "qradar"

    def test_connection(self) -> bool:
        """Test connectivity to QRadar by fetching server info."""
        try:
            resp = self._get("/api/system/about")
            if resp and "external_version" in resp:
                logger.info(
                    "Connected to QRadar %s at %s",
                    resp.get("external_version", "unknown"),
                    self._base_url,
                )
                return True
            logger.error("Unexpected response from QRadar: %s", resp)
            return False
        except Exception:
            logger.exception("Failed to connect to QRadar at %s", self._base_url)
            return False

    def fetch_offenses(self, since: datetime) -> Iterator[NormalizedOffense]:
        """Fetch offenses updated since the given timestamp.

        Queries the QRadar offenses API with a filter on last_updated_time
        and returns normalized offense objects sorted chronologically.
        """
        since_ms = int(since.timestamp() * _MS_TO_SEC)

        filter_parts = [f"last_updated_time > {since_ms}"]
        if self._offense_status_filter:
            filter_parts.append(f"status = {self._offense_status_filter}")
        if self._min_magnitude > 1:
            filter_parts.append(f"magnitude >= {self._min_magnitude}")

        filter_str = " AND ".join(filter_parts)
        fields = ",".join(self._offense_fields)

        logger.info("Fetching QRadar offenses since %s (filter: %s)", since.isoformat(), filter_str)

        offenses = self._get(
            "/api/siem/offenses",
            params={
                "filter": filter_str,
                "fields": fields,
                "sort": "+last_updated_time",
            },
        )

        if not offenses:
            logger.info("No new offenses found")
            return

        logger.info("Found %d new/updated offenses", len(offenses))

        for offense_data in offenses:
            try:
                yield self._normalize_offense(offense_data)
            except Exception:
                logger.exception(
                    "Failed to normalize offense %s",
                    offense_data.get("id", "unknown"),
                )

    def get_offense_iocs(self, offense: NormalizedOffense) -> NormalizedOffense:
        """Enrich a normalized offense with IoCs from QRadar.

        Resolves source/destination IPs, maps the offense_source field,
        and extracts additional IoCs from the offense description.
        """
        raw = offense.raw_event
        offense_id = offense.offense_id
        iocs: list[IoC] = []

        # 1. Resolve source IPs
        source_ids = raw.get("source_address_ids", [])
        for ip in self._resolve_source_addresses(source_ids):
            iocs.append(map_qradar_source_ip(ip, offense_id))

        # 2. Resolve destination IPs
        dest_ids = raw.get("local_destination_address_ids", [])
        for ip in self._resolve_destination_addresses(dest_ids):
            iocs.append(map_qradar_destination_ip(ip, offense_id))

        # 3. Map offense_source based on offense_type
        offense_source = raw.get("offense_source", "")
        offense_type = raw.get("offense_type", -1)
        if offense_source:
            source_ioc = map_offense_source(offense_source, offense_type, offense_id)
            if source_ioc:
                iocs.append(source_ioc)

        # 4. Extract IoCs from the offense description text
        if offense.description:
            text_iocs = extract_iocs_from_text(
                offense.description,
                exclude_private_ips=True,
                source_comment=f"Extracted from QRadar offense #{offense_id} description",
            )
            iocs.extend(text_iocs)

        # Deduplicate by (type, value)
        seen: set[tuple[str, str]] = set()
        unique_iocs: list[IoC] = []
        for ioc in iocs:
            key = (ioc.type.value, ioc.value)
            if key not in seen:
                seen.add(key)
                unique_iocs.append(ioc)

        offense.iocs = unique_iocs
        logger.info(
            "Extracted %d unique IoCs from offense %s", len(unique_iocs), offense_id
        )
        return offense

    def _normalize_offense(self, data: dict[str, Any]) -> NormalizedOffense:
        """Convert raw QRadar offense JSON to a NormalizedOffense."""
        # Parse timestamp (QRadar uses milliseconds since epoch)
        last_updated_ms = data.get("last_updated_time", 0)
        timestamp = datetime.fromtimestamp(last_updated_ms / _MS_TO_SEC, tz=timezone.utc)

        # Extract categories list
        categories = data.get("categories", [])
        if isinstance(categories, list):
            categories = [str(c) for c in categories]
        else:
            categories = []

        # Extract rules
        rules_raw = data.get("rules", [])
        rules = []
        if isinstance(rules_raw, list):
            for r in rules_raw:
                if isinstance(r, dict):
                    rules.append(r.get("name", str(r.get("id", ""))))
                else:
                    rules.append(str(r))

        return NormalizedOffense(
            offense_id=str(data["id"]),
            siem_type=self.siem_type,
            title=data.get("description", f"QRadar Offense #{data['id']}"),
            description=data.get("description", ""),
            severity=data.get("magnitude", 5),
            timestamp=timestamp,
            raw_event=data,
            categories=categories,
            rules=rules,
        )

    def _resolve_source_addresses(self, address_ids: list[int]) -> list[str]:
        """Resolve QRadar source address IDs to IP strings."""
        ips = []
        for addr_id in address_ids[:50]:  # Limit to avoid too many API calls
            try:
                result = self._get(f"/api/siem/source_addresses/{addr_id}")
                if result and "source_ip" in result:
                    ips.append(result["source_ip"])
            except Exception:
                logger.debug("Could not resolve source address %d", addr_id)
        return ips

    def _resolve_destination_addresses(self, address_ids: list[int]) -> list[str]:
        """Resolve QRadar local destination address IDs to IP strings."""
        ips = []
        for addr_id in address_ids[:50]:
            try:
                result = self._get(f"/api/siem/local_destination_addresses/{addr_id}")
                if result and "local_destination_ip" in result:
                    ips.append(result["local_destination_ip"])
            except Exception:
                logger.debug("Could not resolve destination address %d", addr_id)
        return ips

    def _get(self, endpoint: str, params: dict | None = None) -> Any:
        """Make a GET request to the QRadar API with retry logic."""
        url = f"{self._base_url}{endpoint}"

        for attempt in range(3):
            try:
                resp = self._session.get(url, params=params, timeout=30)
                resp.raise_for_status()
                return resp.json()
            except requests.exceptions.RequestException:
                if attempt == 2:
                    raise
                wait = 2 ** (attempt + 1)
                logger.warning(
                    "QRadar API request to %s failed (attempt %d/3), retrying in %ds",
                    endpoint,
                    attempt + 1,
                    wait,
                )
                time.sleep(wait)
        return None
