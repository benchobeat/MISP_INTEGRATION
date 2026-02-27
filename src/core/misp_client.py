"""MISP API client wrapper using PyMISP.

Handles event creation, attribute management, deduplication,
tagging, and sightings for the SIEM integration.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from pymisp import MISPAttribute, MISPEvent, MISPSighting, PyMISP

from core.models import IoC, NormalizedOffense

logger = logging.getLogger(__name__)

MAX_RETRIES = 3
RETRY_BACKOFF_BASE = 2  # seconds


class MISPClient:
    """Wrapper around PyMISP for SIEM integration operations."""

    def __init__(
        self,
        url: str,
        api_key: str,
        verify_ssl: bool = True,
        distribution: int = 0,
        threat_level_default: int = 2,
        analysis_default: int = 1,
        tags: list[str] | None = None,
        publish: bool = False,
    ):
        self.url = url.rstrip("/")
        self.distribution = distribution
        self.threat_level_default = threat_level_default
        self.analysis_default = analysis_default
        self.default_tags = tags or []
        self.publish = publish

        self._misp = PyMISP(self.url, api_key, ssl=verify_ssl, timeout=30)

    def test_connection(self) -> bool:
        """Verify connectivity and authentication to MISP."""
        try:
            result = self._misp.get_user("me")
            if isinstance(result, dict) and "User" in result:
                user = result["User"]
                logger.info(
                    "Connected to MISP as %s (org: %s)",
                    user.get("email", "unknown"),
                    user.get("org_id", "unknown"),
                )
                return True
            logger.error("Unexpected response from MISP: %s", result)
            return False
        except Exception:
            logger.exception("Failed to connect to MISP")
            return False

    def find_event_by_offense(self, offense: NormalizedOffense) -> MISPEvent | None:
        """Search for an existing MISP event for this offense (deduplication)."""
        tag = offense.offense_tag
        try:
            result = self._misp.search(
                controller="events",
                tags=[tag],
                limit=1,
                pythonify=True,
            )
            if result and isinstance(result, list) and len(result) > 0:
                logger.info(
                    "Found existing MISP event for offense %s: event_id=%s",
                    offense.offense_id,
                    result[0].id,
                )
                return result[0]
        except Exception:
            logger.exception(
                "Error searching MISP for offense %s", offense.offense_id
            )
        return None

    def create_event_from_offense(self, offense: NormalizedOffense) -> MISPEvent | None:
        """Create a new MISP event from a normalized offense.

        If an event already exists for this offense (same offense_tag),
        it adds new attributes to the existing event instead.
        """
        existing = self.find_event_by_offense(offense)
        if existing:
            return self._update_existing_event(existing, offense)
        return self._create_new_event(offense)

    def _create_new_event(self, offense: NormalizedOffense) -> MISPEvent | None:
        """Create a brand new MISP event."""
        event = MISPEvent()
        event.info = f"[{offense.siem_type.upper()}] Offense #{offense.offense_id}: {offense.title}"
        event.distribution = self.distribution
        event.threat_level_id = offense.threat_level.value
        event.analysis = self.analysis_default
        event.date = offense.timestamp.strftime("%Y-%m-%d")

        # Add default tags
        for tag_name in self.default_tags:
            event.add_tag(tag_name)

        # Add SIEM-specific tags
        event.add_tag(offense.siem_tag)
        event.add_tag(offense.offense_tag)

        # Add category tags if available
        for cat in offense.categories:
            event.add_tag(f"qradar:category={cat}")

        # Add IoCs as attributes
        for ioc in offense.iocs:
            attr = self._build_attribute(ioc, offense)
            event.add_attribute(**attr)

        # Add offense description as a comment attribute
        if offense.description:
            event.add_attribute(
                type="comment",
                value=offense.description,
                category="Other",
                comment=f"Original offense description from {offense.siem_type.upper()}",
                to_ids=False,
            )

        result = self._api_call_with_retry(self._misp.add_event, event, pythonify=True)

        if result and hasattr(result, "id"):
            logger.info(
                "Created MISP event %s for offense %s with %d IoCs",
                result.id,
                offense.offense_id,
                len(offense.iocs),
            )
            if self.publish:
                try:
                    self._api_call_with_retry(self._misp.publish, result.id)
                    logger.info("Published MISP event %s", result.id)
                except Exception:
                    logger.warning(
                        "Created event %s but failed to publish it",
                        result.id,
                    )
            return result

        logger.error(
            "Failed to create MISP event for offense %s: %s",
            offense.offense_id,
            result,
        )
        return None

    def _update_existing_event(
        self, event: MISPEvent, offense: NormalizedOffense
    ) -> MISPEvent | None:
        """Add new attributes to an existing event and register a sighting."""
        existing_values = {attr.value for attr in event.Attribute}
        new_iocs = [ioc for ioc in offense.iocs if ioc.value not in existing_values]

        if not new_iocs:
            logger.info(
                "No new IoCs to add to event %s for offense %s",
                event.id,
                offense.offense_id,
            )
            # Still register a sighting for existing IoCs
            self._add_sightings(event, offense)
            return event

        for ioc in new_iocs:
            attr = self._build_attribute(ioc, offense)
            misp_attr = MISPAttribute()
            misp_attr.type = attr["type"]
            misp_attr.value = attr["value"]
            misp_attr.category = attr["category"]
            misp_attr.comment = attr["comment"]
            misp_attr.to_ids = attr["to_ids"]

            self._api_call_with_retry(
                self._misp.add_attribute, event.id, misp_attr, pythonify=True
            )

        logger.info(
            "Added %d new IoCs to existing event %s for offense %s",
            len(new_iocs),
            event.id,
            offense.offense_id,
        )

        self._add_sightings(event, offense)
        return event

    def _add_sightings(self, event: MISPEvent, offense: NormalizedOffense) -> None:
        """Add sightings for IoCs in the event."""
        for attr in event.Attribute:
            try:
                sighting = MISPSighting()
                sighting.source = f"{offense.siem_type}:offense_{offense.offense_id}"
                sighting.timestamp = int(offense.timestamp.timestamp())
                self._misp.add_sighting(sighting, attr.id)
            except Exception:
                logger.debug(
                    "Could not add sighting for attribute %s", attr.id
                )

    def _build_attribute(self, ioc: IoC, offense: NormalizedOffense) -> dict[str, Any]:
        """Build a MISP attribute dict from an IoC."""
        return {
            "type": ioc.type.value,
            "value": ioc.value,
            "category": ioc.category.value,
            "comment": ioc.comment
            or f"Extracted from {offense.siem_type.upper()} offense #{offense.offense_id}",
            "to_ids": ioc.to_ids,
        }

    def _api_call_with_retry(self, func, *args, **kwargs) -> Any:
        """Execute a MISP API call with exponential backoff retry.

        Only retries on transient errors (network, timeout, server errors).
        Non-retryable errors (auth, validation, programming) are raised immediately.
        """
        _non_retryable = (TypeError, ValueError, KeyError, AttributeError)

        for attempt in range(MAX_RETRIES):
            try:
                return func(*args, **kwargs)
            except _non_retryable:
                logger.exception(
                    "MISP API call %s failed with non-retryable error",
                    getattr(func, "__name__", str(func)),
                )
                raise
            except Exception:
                if attempt == MAX_RETRIES - 1:
                    logger.exception(
                        "MISP API call %s failed after %d retries",
                        getattr(func, "__name__", str(func)),
                        MAX_RETRIES,
                    )
                    raise
                wait = RETRY_BACKOFF_BASE ** (attempt + 1)
                logger.warning(
                    "MISP API call %s failed (attempt %d/%d), retrying in %ds",
                    getattr(func, "__name__", str(func)),
                    attempt + 1,
                    MAX_RETRIES,
                    wait,
                )
                time.sleep(wait)
        return None
