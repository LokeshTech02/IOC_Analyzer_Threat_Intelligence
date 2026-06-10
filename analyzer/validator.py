"""IOC detection and validation helpers."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

EMAIL_REGEX = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}$")
MD5_REGEX = re.compile(r"^[A-Fa-f0-9]{32}$")
SHA1_REGEX = re.compile(r"^[A-Fa-f0-9]{40}$")
SHA256_REGEX = re.compile(r"^[A-Fa-f0-9]{64}$")
DOMAIN_REGEX = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$"
)
URL_REGEX = re.compile(r"^https?://", re.IGNORECASE)


def is_valid_ipv4(value: str) -> bool:
    """Return True when the value is a valid IPv4 address."""
    try:
        return isinstance(ipaddress.ip_address(value), ipaddress.IPv4Address)
    except ValueError:
        return False


def is_valid_ipv6(value: str) -> bool:
    """Return True when the value is a valid IPv6 address."""
    try:
        return isinstance(ipaddress.ip_address(value), ipaddress.IPv6Address)
    except ValueError:
        return False


def is_valid_domain(value: str) -> bool:
    """Return True when the value is a valid DNS domain."""
    if len(value) > 253 or "_" in value:
        return False
    return bool(DOMAIN_REGEX.fullmatch(value))


def is_valid_url(value: str) -> bool:
    """Return True when the value is an HTTP or HTTPS URL."""
    if not URL_REGEX.match(value):
        return False
    parsed = urlparse(value)
    return bool(parsed.scheme and parsed.netloc)


def is_valid_email(value: str) -> bool:
    """Return True when the value is an email address."""
    return bool(EMAIL_REGEX.fullmatch(value))


def detect_ioc_type(value: str) -> str:
    """Identify the IOC type using ordered validation checks."""
    normalized = value.strip()
    if not normalized:
        return "Unknown"
    if is_valid_ipv4(normalized):
        return "IPv4"
    if is_valid_ipv6(normalized):
        return "IPv6"
    if is_valid_url(normalized):
        return "URL"
    if is_valid_email(normalized):
        return "Email"
    if MD5_REGEX.fullmatch(normalized):
        return "MD5"
    if SHA1_REGEX.fullmatch(normalized):
        return "SHA1"
    if SHA256_REGEX.fullmatch(normalized):
        return "SHA256"
    if is_valid_domain(normalized):
        return "Domain"
    return "Unknown"
