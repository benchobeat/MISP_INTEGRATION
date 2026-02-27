"""IoC extraction and classification from free text.

Extracts indicators (IPs, domains, URLs, hashes, emails) from
unstructured text fields such as QRadar offense descriptions,
event payloads, or log messages using regex patterns.
"""

from __future__ import annotations

import re
from ipaddress import IPv4Address, IPv4Network, ip_address

from core.models import IoC, IoCType

# Private/reserved IP ranges to exclude
_PRIVATE_NETWORKS = [
    IPv4Network("10.0.0.0/8"),
    IPv4Network("172.16.0.0/12"),
    IPv4Network("192.168.0.0/16"),
    IPv4Network("127.0.0.0/8"),
    IPv4Network("169.254.0.0/16"),
    IPv4Network("0.0.0.0/8"),
    IPv4Network("224.0.0.0/4"),  # Multicast
    IPv4Network("255.255.255.255/32"),
]

# Regex patterns
_IPV4_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)

_DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)"
    r"+(?:[a-zA-Z]{2,63})\b"
)

_URL_PATTERN = re.compile(
    r"https?://[^\s<>\"'}\])]+",
    re.IGNORECASE,
)

_MD5_PATTERN = re.compile(r"\b[a-fA-F0-9]{32}\b")
_SHA1_PATTERN = re.compile(r"\b[a-fA-F0-9]{40}\b")
_SHA256_PATTERN = re.compile(r"\b[a-fA-F0-9]{64}\b")

_EMAIL_PATTERN = re.compile(
    r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"
)

# Common domains to exclude (noise reduction)
_EXCLUDED_DOMAINS = {
    "example.com",
    "example.org",
    "example.net",
    "localhost",
    "localhost.localdomain",
    "schema.org",
    "w3.org",
    "xml.org",
    "googleapis.com",
    "microsoft.com",
    "windowsupdate.com",
    "windows.net",
    "google.com",
    "github.com",
    "digicert.com",
    "verisign.com",
    "symantec.com",
    "letsencrypt.org",
    "update.windows.com",
    "windowsupdate.microsoft.com",
}

# File extensions that look like TLDs but are not real domains
_FALSE_POSITIVE_TLDS = {
    "exe", "dll", "sys", "bat", "cmd", "scr", "pif",
    "msi", "jar", "ps1", "vbs", "wsf", "hta",
    "doc", "docx", "xls", "xlsx", "ppt", "pptx", "pdf",
    "zip", "rar", "7z", "tar", "gz", "bz2",
    "txt", "csv", "log", "tmp", "bak", "old", "orig",
    "png", "jpg", "jpeg", "gif", "bmp", "svg", "ico",
    "html", "htm", "xml", "json", "yaml", "yml",
    "cfg", "conf", "ini", "env",
    "py", "js", "ts", "rb", "go", "rs", "java", "cpp", "sh",
    "local", "internal", "source", "code", "test",
}


def is_private_ip(ip_str: str) -> bool:
    """Check if an IP address is in a private/reserved range."""
    try:
        addr = ip_address(ip_str)
        if not isinstance(addr, IPv4Address):
            return False
        return any(addr in net for net in _PRIVATE_NETWORKS)
    except ValueError:
        return False


def classify_indicator(value: str) -> IoCType | None:
    """Classify an indicator string to its most likely MISP IoC type.

    Returns None if the value cannot be classified.
    """
    value = value.strip()
    if not value:
        return None

    # Check URL first (most specific)
    if _URL_PATTERN.match(value):
        return IoCType.URL

    # Check hashes (by length specificity)
    if _SHA256_PATTERN.fullmatch(value):
        return IoCType.SHA256
    if _SHA1_PATTERN.fullmatch(value):
        return IoCType.SHA1
    if _MD5_PATTERN.fullmatch(value):
        return IoCType.MD5

    # Check email
    if _EMAIL_PATTERN.fullmatch(value):
        return IoCType.EMAIL_SRC

    # Check IPv4
    if _IPV4_PATTERN.fullmatch(value):
        return IoCType.IP_SRC

    # Check domain
    if _DOMAIN_PATTERN.fullmatch(value) and "." in value:
        return IoCType.DOMAIN

    return None


def extract_iocs_from_text(
    text: str,
    exclude_private_ips: bool = True,
    source_comment: str = "",
) -> list[IoC]:
    """Extract all IoCs from unstructured text.

    Scans the text for IPs, domains, URLs, hashes, and emails.
    Deduplicates results and optionally filters private IPs.

    Args:
        text: The text to scan for indicators.
        exclude_private_ips: If True, skip RFC 1918 and reserved IPs.
        source_comment: Comment to add to each extracted IoC.

    Returns:
        List of unique IoC objects found in the text.
    """
    if not text:
        return []

    seen: set[str] = set()
    iocs: list[IoC] = []

    def _add(ioc_type: IoCType, value: str) -> None:
        key = f"{ioc_type.value}:{value}"
        if key not in seen:
            seen.add(key)
            iocs.append(IoC(type=ioc_type, value=value, comment=source_comment))

    # Extract URLs first (before domain/IP extraction picks up parts of URLs)
    urls_found: set[str] = set()
    for match in _URL_PATTERN.finditer(text):
        url = match.group().rstrip(".,;:)")
        urls_found.add(url)
        _add(IoCType.URL, url)

    # Extract hashes (longest first to avoid partial matches)
    for match in _SHA256_PATTERN.finditer(text):
        _add(IoCType.SHA256, match.group().lower())

    for match in _SHA1_PATTERN.finditer(text):
        val = match.group().lower()
        # Skip if it was part of a SHA256
        if f"{val}" not in {ioc.value[:40] for ioc in iocs if ioc.type == IoCType.SHA256}:
            _add(IoCType.SHA1, val)

    for match in _MD5_PATTERN.finditer(text):
        val = match.group().lower()
        # Skip if it was part of a longer hash
        longer_hashes = {
            ioc.value
            for ioc in iocs
            if ioc.type in (IoCType.SHA1, IoCType.SHA256)
        }
        if not any(val in h for h in longer_hashes):
            _add(IoCType.MD5, val)

    # Extract emails
    for match in _EMAIL_PATTERN.finditer(text):
        _add(IoCType.EMAIL_SRC, match.group().lower())

    # Extract IPs
    for match in _IPV4_PATTERN.finditer(text):
        ip = match.group()
        # Skip IPs that are part of a URL already captured
        if any(ip in url for url in urls_found):
            continue
        if exclude_private_ips and is_private_ip(ip):
            continue
        _add(IoCType.IP_SRC, ip)

    # Extract domains
    for match in _DOMAIN_PATTERN.finditer(text):
        domain = match.group().lower().rstrip(".")
        if domain in _EXCLUDED_DOMAINS:
            continue
        # Skip domains that are part of a URL or email already captured
        if any(domain in url for url in urls_found):
            continue
        if any(domain in ioc.value for ioc in iocs if ioc.type == IoCType.EMAIL_SRC):
            continue
        # Basic TLD validation (must have at least 2 parts)
        parts = domain.split(".")
        if len(parts) >= 2 and len(parts[-1]) >= 2:
            # Skip filenames that look like domains (e.g., "malware.exe")
            if parts[-1].lower() in _FALSE_POSITIVE_TLDS:
                continue
            _add(IoCType.DOMAIN, domain)

    return iocs
