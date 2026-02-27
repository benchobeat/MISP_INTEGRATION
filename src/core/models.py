"""Data models for the MISP SIEM Integration."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum


class IoCType(str, Enum):
    """MISP attribute types for IoCs."""

    IP_SRC = "ip-src"
    IP_DST = "ip-dst"
    DOMAIN = "domain"
    HOSTNAME = "hostname"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    EMAIL_SRC = "email-src"
    EMAIL_DST = "email-dst"
    FILENAME = "filename"


class MISPCategory(str, Enum):
    """MISP attribute categories."""

    NETWORK_ACTIVITY = "Network activity"
    PAYLOAD_DELIVERY = "Payload delivery"
    ARTIFACTS_DROPPED = "Artifacts dropped"
    EXTERNAL_ANALYSIS = "External analysis"


class ThreatLevel(int, Enum):
    """MISP threat level IDs."""

    HIGH = 1
    MEDIUM = 2
    LOW = 3
    UNDEFINED = 4


IOC_TYPE_TO_CATEGORY: dict[IoCType, MISPCategory] = {
    IoCType.IP_SRC: MISPCategory.NETWORK_ACTIVITY,
    IoCType.IP_DST: MISPCategory.NETWORK_ACTIVITY,
    IoCType.DOMAIN: MISPCategory.NETWORK_ACTIVITY,
    IoCType.HOSTNAME: MISPCategory.NETWORK_ACTIVITY,
    IoCType.URL: MISPCategory.NETWORK_ACTIVITY,
    IoCType.MD5: MISPCategory.PAYLOAD_DELIVERY,
    IoCType.SHA1: MISPCategory.PAYLOAD_DELIVERY,
    IoCType.SHA256: MISPCategory.PAYLOAD_DELIVERY,
    IoCType.EMAIL_SRC: MISPCategory.PAYLOAD_DELIVERY,
    IoCType.EMAIL_DST: MISPCategory.PAYLOAD_DELIVERY,
    IoCType.FILENAME: MISPCategory.ARTIFACTS_DROPPED,
}


@dataclass
class IoC:
    """An individual Indicator of Compromise."""

    type: IoCType
    value: str
    comment: str = ""
    to_ids: bool = True

    @property
    def category(self) -> MISPCategory:
        return IOC_TYPE_TO_CATEGORY.get(self.type, MISPCategory.NETWORK_ACTIVITY)


@dataclass
class NormalizedOffense:
    """A SIEM offense/alert normalized to a common format.

    This is the intermediate representation between a SIEM-specific alert
    and a MISP event. Each SIEM connector converts its native alert format
    into this normalized structure.
    """

    offense_id: str
    siem_type: str  # e.g., "qradar", "fortisiem", "netwitness"
    title: str
    description: str
    severity: int  # 1-10 normalized
    source_ip: str | None = None
    destination_ip: str | None = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    raw_event: dict = field(default_factory=dict)
    iocs: list[IoC] = field(default_factory=list)
    categories: list[str] = field(default_factory=list)
    rules: list[str] = field(default_factory=list)

    @property
    def threat_level(self) -> ThreatLevel:
        """Map SIEM severity (1-10) to MISP threat level (1-4)."""
        if self.severity >= 8:
            return ThreatLevel.HIGH
        if self.severity >= 6:
            return ThreatLevel.MEDIUM
        if self.severity >= 4:
            return ThreatLevel.LOW
        return ThreatLevel.UNDEFINED

    @property
    def siem_tag(self) -> str:
        """Tag identifying the source SIEM."""
        return f"siem:{self.siem_type}"

    @property
    def offense_tag(self) -> str:
        """Tag identifying the specific offense."""
        return f"{self.siem_type}:offense_id={self.offense_id}"
