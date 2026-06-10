"""Risk scoring engine for IOC Analyzer."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from urllib.parse import urlparse

SUSPICIOUS_TLDS = {
    "biz",
    "click",
    "country",
    "gq",
    "kim",
    "link",
    "monster",
    "ru",
    "top",
    "work",
    "xyz",
}
CRYPTO_KEYWORDS = {"btc", "crypto", "coin", "wallet", "eth", "token", "blockchain"}
BRAND_KEYWORDS = {
    "microsoft365": {"microsoft.com", "office.com", "office365.com"},
    "office365": {"microsoft.com", "office.com", "office365.com"},
    "paypal": {"paypal.com"},
    "okta": {"okta.com"},
    "onedrive": {"microsoft.com", "live.com"},
    "appleid": {"apple.com"},
    "adobe": {"adobe.com"},
}


def apply_vt_score_adjustments(
    score: int, vt_reputation: dict[str, int | bool] | None
) -> tuple[int, list[str]]:
    """Apply VirusTotal-derived score adjustments."""
    if not vt_reputation or not vt_reputation.get("vt_enabled"):
        return min(score, 100), []

    adjusted_score = score
    reasons: list[str] = []
    malicious_votes = int(vt_reputation.get("malicious_votes", 0))
    reputation = int(vt_reputation.get("reputation", 0))

    if malicious_votes > 25:
        adjusted_score += 60
        reasons.append("VirusTotal reported more than 25 malicious votes")
    elif malicious_votes > 10:
        adjusted_score += 40
        reasons.append("VirusTotal reported more than 10 malicious votes")

    if reputation < 0:
        adjusted_score += 20
        reasons.append("VirusTotal reputation score is negative")

    return min(adjusted_score, 100), reasons


def apply_abuseipdb_score_adjustments(
    score: int, abuseipdb_reputation: dict[str, int | str | bool] | None
) -> tuple[int, list[str]]:
    """Apply AbuseIPDB-derived score adjustments."""
    if not abuseipdb_reputation or not abuseipdb_reputation.get("enabled"):
        return min(score, 100), []

    adjusted_score = score
    reasons: list[str] = []
    confidence_score = int(abuseipdb_reputation.get("abuse_confidence_score", 0))

    if confidence_score >= 80:
        adjusted_score += 40
        reasons.append("AbuseIPDB confidence score is 80 or higher")
    elif confidence_score >= 50:
        adjusted_score += 25
        reasons.append("AbuseIPDB confidence score is 50 or higher")
    elif confidence_score >= 20:
        adjusted_score += 10
        reasons.append("AbuseIPDB confidence score is elevated")

    return min(adjusted_score, 100), reasons


def _pick_host(ioc: str, ioc_type: str) -> str:
    """Normalize the hostname-like portion for domain and URL analysis."""
    if ioc_type == "URL":
        return (urlparse(ioc).hostname or "").lower()
    return ioc.lower()


def _contains_keyword(value: str, keywords: Iterable[str]) -> bool:
    """Return True if any keyword appears in the string."""
    lowered = value.lower()
    return any(keyword in lowered for keyword in keywords)


def _looks_random_domain(host: str) -> bool:
    """Heuristic for algorithmic-looking domains."""
    label = host.split(".")[0]
    if len(label) < 12:
        return False
    vowel_count = sum(char in "aeiou" for char in label.lower())
    digit_count = sum(char.isdigit() for char in label)
    consonant_clusters = re.search(r"[bcdfghjklmnpqrstvwxyz]{5,}", label.lower())
    return vowel_count <= 2 or digit_count >= 4 or bool(consonant_clusters)


def _has_brand_impersonation(host: str) -> bool:
    """Return True when a host references a brand outside its official domains."""
    for brand, official_suffixes in BRAND_KEYWORDS.items():
        if brand in host and not any(host.endswith(suffix) for suffix in official_suffixes):
            return True
    return False


def score_ioc(
    ioc: str,
    ioc_type: str,
    vt_reputation: dict[str, int | bool] | None = None,
    abuseipdb_reputation: dict[str, int | str | bool] | None = None,
) -> tuple[int, list[str]]:
    """Assign a risk score and rationale list to an IOC."""
    if ioc_type == "Unknown":
        return 10, ["IOC type could not be validated"]

    score = 0
    reasons: list[str] = []

    if ioc_type in {"IPv4", "IPv6"}:
        address = ipaddress.ip_address(ioc)
        if address.is_private or address.is_loopback or address.is_link_local:
            score = max(score, 5)
            reasons.append("Private or local IP range")
        else:
            score = max(score, 25)
            reasons.append("Publicly routable IP address")
        if address.is_multicast or address.is_reserved:
            score += 10
            reasons.append("Special-use network range")

    if ioc_type in {"Domain", "URL"}:
        host = _pick_host(ioc, ioc_type)
        parts = host.split(".")
        tld = parts[-1] if len(parts) > 1 else ""
        if tld in SUSPICIOUS_TLDS:
            score = max(score, 60)
            reasons.append("Suspicious top-level domain")
        if _contains_keyword(host, CRYPTO_KEYWORDS):
            score = max(score, 70)
            reasons.append("Cryptocurrency-related domain pattern")
        if _looks_random_domain(host):
            score = max(score, 75)
            reasons.append("Long random-looking domain")
        if _has_brand_impersonation(host):
            score = max(score, 65)
            reasons.append("Potential brand impersonation pattern")
        if ioc_type == "URL" and urlparse(ioc).query:
            score += 5
            reasons.append("URL contains query parameters")
        if score == 0:
            score = 20
            reasons.append("Standard domain or URL indicator")

    if ioc_type in {"MD5", "SHA1", "SHA256"}:
        score = max(score, 50)
        reasons.append("File hash requires enrichment context")

    if ioc_type == "Email":
        domain_part = ioc.split("@", maxsplit=1)[-1]
        score = max(score, 35)
        reasons.append("Email indicators may support phishing investigations")
        if _has_brand_impersonation(domain_part):
            score = max(score, 65)
            reasons.append("Potential brand impersonation pattern")

    score, vt_reasons = apply_vt_score_adjustments(score, vt_reputation)
    reasons.extend(vt_reasons)
    score, abuseipdb_reasons = apply_abuseipdb_score_adjustments(score, abuseipdb_reputation)
    reasons.extend(abuseipdb_reasons)
    return min(score, 100), reasons
