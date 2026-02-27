"""IoC type mapping from SIEM-specific formats to MISP attribute types.

This module provides the logic to determine which MISP attribute type
an indicator should be mapped to, based on how it was obtained from
the SIEM (source IP, destination IP, domain from DNS, etc.).
"""

from __future__ import annotations

from core.models import IoC, IoCType


# QRadar offense_type ID to description mapping
QRADAR_OFFENSE_TYPES: dict[int, str] = {
    0: "Source IP",
    1: "Destination IP",
    2: "Event Name",
    3: "Username",
    4: "Source MAC",
    5: "Destination MAC",
    6: "Log Source",
    7: "Hostname",
    8: "Source Port",
    9: "Destination Port",
    10: "Source IPv6",
    11: "Destination IPv6",
    12: "Source ASN",
    13: "Destination ASN",
    14: "Rule",
    15: "App ID",
}


def map_qradar_source_ip(ip: str, offense_id: str) -> IoC:
    """Map a QRadar source address to a MISP ip-src attribute."""
    return IoC(
        type=IoCType.IP_SRC,
        value=ip,
        comment=f"Source IP from QRadar offense #{offense_id}",
    )


def map_qradar_destination_ip(ip: str, offense_id: str) -> IoC:
    """Map a QRadar destination address to a MISP ip-dst attribute."""
    return IoC(
        type=IoCType.IP_DST,
        value=ip,
        comment=f"Destination IP from QRadar offense #{offense_id}",
    )


def map_offense_source(
    offense_source: str, offense_type: int, offense_id: str
) -> IoC | None:
    """Map the QRadar offense_source field based on offense_type.

    The offense_source field in QRadar changes its meaning based on
    offense_type. For example, if offense_type=0, the offense_source
    is a source IP; if offense_type=7, it's a hostname.
    """
    from core.ioc_extractor import classify_indicator

    if offense_type in (0, 10):  # Source IP / Source IPv6
        return IoC(
            type=IoCType.IP_SRC,
            value=offense_source,
            comment=f"Offense source (type=IP) from QRadar offense #{offense_id}",
        )
    if offense_type in (1, 11):  # Destination IP / Destination IPv6
        return IoC(
            type=IoCType.IP_DST,
            value=offense_source,
            comment=f"Offense source (type=IP) from QRadar offense #{offense_id}",
        )
    if offense_type == 3:  # Username
        return None  # Usernames are not IoCs we push to MISP
    if offense_type == 7:  # Hostname
        return IoC(
            type=IoCType.HOSTNAME,
            value=offense_source,
            comment=f"Hostname from QRadar offense #{offense_id}",
        )

    # For other types, try to auto-detect the indicator type
    detected_type = classify_indicator(offense_source)
    if detected_type:
        return IoC(
            type=detected_type,
            value=offense_source,
            comment=f"Auto-detected from QRadar offense #{offense_id} "
            f"(offense_type={offense_type})",
        )

    return None


def map_severity_to_threat_level(magnitude: int) -> int:
    """Map QRadar magnitude (1-10) to MISP threat_level_id (1-4).

    | QRadar Magnitude | MISP threat_level_id | Level     |
    |------------------|---------------------|-----------|
    | 8-10             | 1                   | High      |
    | 6-7              | 2                   | Medium    |
    | 4-5              | 3                   | Low       |
    | 1-3              | 4                   | Undefined |
    """
    if magnitude >= 8:
        return 1
    if magnitude >= 6:
        return 2
    if magnitude >= 4:
        return 3
    return 4
