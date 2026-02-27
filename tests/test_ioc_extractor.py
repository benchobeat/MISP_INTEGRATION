"""Tests for the IoC extractor module."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from core.ioc_extractor import (
    classify_indicator,
    extract_iocs_from_text,
    is_private_ip,
)
from core.models import IoCType


class TestIsPrivateIP:
    def test_rfc1918_10(self):
        assert is_private_ip("10.0.0.1") is True

    def test_rfc1918_172(self):
        assert is_private_ip("172.16.0.1") is True

    def test_rfc1918_192(self):
        assert is_private_ip("192.168.1.1") is True

    def test_loopback(self):
        assert is_private_ip("127.0.0.1") is True

    def test_public_ip(self):
        assert is_private_ip("8.8.8.8") is False

    def test_public_ip_2(self):
        assert is_private_ip("203.0.113.50") is False

    def test_invalid(self):
        assert is_private_ip("not-an-ip") is False

    def test_multicast(self):
        assert is_private_ip("224.0.0.1") is True


class TestClassifyIndicator:
    def test_ipv4(self):
        assert classify_indicator("8.8.8.8") == IoCType.IP_SRC

    def test_domain(self):
        assert classify_indicator("malware.evil.com") == IoCType.DOMAIN

    def test_url(self):
        assert classify_indicator("https://evil.com/malware.exe") == IoCType.URL

    def test_md5(self):
        assert classify_indicator("d41d8cd98f00b204e9800998ecf8427e") == IoCType.MD5

    def test_sha1(self):
        assert classify_indicator("da39a3ee5e6b4b0d3255bfef95601890afd80709") == IoCType.SHA1

    def test_sha256(self):
        assert classify_indicator(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ) == IoCType.SHA256

    def test_email(self):
        assert classify_indicator("attacker@evil.com") == IoCType.EMAIL_SRC

    def test_empty(self):
        assert classify_indicator("") is None

    def test_unknown(self):
        assert classify_indicator("just some text") is None


class TestExtractIocsFromText:
    def test_extract_ips(self):
        text = "Connection from 203.0.113.50 to 198.51.100.10 detected"
        iocs = extract_iocs_from_text(text)
        values = {ioc.value for ioc in iocs}
        assert "203.0.113.50" in values
        assert "198.51.100.10" in values

    def test_exclude_private_ips(self):
        text = "Traffic from 10.0.0.1 to 203.0.113.50"
        iocs = extract_iocs_from_text(text, exclude_private_ips=True)
        values = {ioc.value for ioc in iocs}
        assert "10.0.0.1" not in values
        assert "203.0.113.50" in values

    def test_include_private_ips(self):
        text = "Traffic from 10.0.0.1 to 203.0.113.50"
        iocs = extract_iocs_from_text(text, exclude_private_ips=False)
        values = {ioc.value for ioc in iocs}
        assert "10.0.0.1" in values
        assert "203.0.113.50" in values

    def test_extract_domains(self):
        text = "DNS query for malware-c2.evil.com from internal host"
        iocs = extract_iocs_from_text(text)
        domains = [ioc.value for ioc in iocs if ioc.type == IoCType.DOMAIN]
        assert "malware-c2.evil.com" in domains

    def test_extract_urls(self):
        text = "Download from https://evil.com/payload.exe detected"
        iocs = extract_iocs_from_text(text)
        urls = [ioc.value for ioc in iocs if ioc.type == IoCType.URL]
        assert "https://evil.com/payload.exe" in urls

    def test_extract_hashes(self):
        text = "File hash: d41d8cd98f00b204e9800998ecf8427e was flagged"
        iocs = extract_iocs_from_text(text)
        hashes = [ioc.value for ioc in iocs if ioc.type == IoCType.MD5]
        assert "d41d8cd98f00b204e9800998ecf8427e" in hashes

    def test_extract_sha256(self):
        text = "SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        iocs = extract_iocs_from_text(text)
        hashes = [ioc.value for ioc in iocs if ioc.type == IoCType.SHA256]
        assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in hashes

    def test_deduplication(self):
        text = "IP 203.0.113.50 seen again: 203.0.113.50"
        iocs = extract_iocs_from_text(text)
        ip_iocs = [ioc for ioc in iocs if ioc.value == "203.0.113.50"]
        assert len(ip_iocs) == 1

    def test_empty_text(self):
        assert extract_iocs_from_text("") == []
        assert extract_iocs_from_text(None) == []

    def test_source_comment(self):
        text = "IP: 8.8.8.8"
        iocs = extract_iocs_from_text(text, source_comment="from test")
        assert iocs[0].comment == "from test"

    def test_complex_text(self):
        """Test extraction from a realistic offense description."""
        text = (
            "Excessive Firewall Denies from 203.0.113.50 targeting 10.0.0.5. "
            "Related domain: malware-c2.evil.com. "
            "Malware hash: d41d8cd98f00b204e9800998ecf8427e. "
            "C2 callback to https://evil.com/beacon?id=12345. "
            "Alert sent to admin@company.com."
        )
        iocs = extract_iocs_from_text(text)
        types = {ioc.type for ioc in iocs}

        assert IoCType.IP_SRC in types
        assert IoCType.URL in types
        assert IoCType.MD5 in types
        # Private IP 10.0.0.5 should be excluded
        values = {ioc.value for ioc in iocs}
        assert "10.0.0.5" not in values
        assert "203.0.113.50" in values
