"""Tests for the IoC mapper module."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from core.ioc_mapper import (
    map_offense_source,
    map_qradar_destination_ip,
    map_qradar_source_ip,
    map_severity_to_threat_level,
)
from core.models import IoCType


class TestMapQRadarSourceIP:
    def test_creates_ip_src(self):
        ioc = map_qradar_source_ip("203.0.113.50", "123")
        assert ioc.type == IoCType.IP_SRC
        assert ioc.value == "203.0.113.50"
        assert "123" in ioc.comment


class TestMapQRadarDestinationIP:
    def test_creates_ip_dst(self):
        ioc = map_qradar_destination_ip("198.51.100.10", "456")
        assert ioc.type == IoCType.IP_DST
        assert ioc.value == "198.51.100.10"
        assert "456" in ioc.comment


class TestMapOffenseSource:
    def test_source_ip_type_0(self):
        ioc = map_offense_source("203.0.113.50", 0, "100")
        assert ioc is not None
        assert ioc.type == IoCType.IP_SRC

    def test_source_ip_type_10_ipv6(self):
        ioc = map_offense_source("2001:db8::1", 10, "100")
        assert ioc is not None
        assert ioc.type == IoCType.IP_SRC

    def test_dest_ip_type_1(self):
        ioc = map_offense_source("198.51.100.10", 1, "100")
        assert ioc is not None
        assert ioc.type == IoCType.IP_DST

    def test_hostname_type_7(self):
        ioc = map_offense_source("server.evil.com", 7, "100")
        assert ioc is not None
        assert ioc.type == IoCType.HOSTNAME
        assert ioc.value == "server.evil.com"

    def test_username_type_3_returns_none(self):
        """Usernames are not IoCs, should return None."""
        ioc = map_offense_source("admin", 3, "100")
        assert ioc is None

    def test_auto_detect_domain(self):
        """Unknown offense_type with a domain value should auto-detect."""
        ioc = map_offense_source("malware.evil.com", 99, "100")
        assert ioc is not None
        assert ioc.type == IoCType.DOMAIN

    def test_auto_detect_url(self):
        ioc = map_offense_source("https://evil.com/malware", 99, "100")
        assert ioc is not None
        assert ioc.type == IoCType.URL


class TestMapSeverityToThreatLevel:
    def test_high(self):
        assert map_severity_to_threat_level(10) == 1
        assert map_severity_to_threat_level(8) == 1

    def test_medium(self):
        assert map_severity_to_threat_level(7) == 2
        assert map_severity_to_threat_level(6) == 2

    def test_low(self):
        assert map_severity_to_threat_level(5) == 3
        assert map_severity_to_threat_level(4) == 3

    def test_undefined(self):
        assert map_severity_to_threat_level(3) == 4
        assert map_severity_to_threat_level(1) == 4
