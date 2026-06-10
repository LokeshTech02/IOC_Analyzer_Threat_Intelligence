"""Threat context inference for IOC Analyzer."""

from __future__ import annotations

import re
from urllib.parse import urlparse

from analyzer.scoring import BRAND_KEYWORDS, CRYPTO_KEYWORDS, SUSPICIOUS_TLDS


def _extract_host(ioc: str, ioc_type: str) -> str:
    """Return a lowercase host-like string for analysis."""
    if ioc_type == "URL":
        return (urlparse(ioc).hostname or "").lower()
    if ioc_type == "Email":
        return ioc.split("@", maxsplit=1)[-1].lower()
    return ioc.lower()


def _looks_random_domain(host: str) -> bool:
    """Heuristic for suspiciously random domain labels."""
    label = host.split(".")[0]
    if len(label) < 12:
        return False
    vowel_count = sum(char in "aeiou" for char in label.lower())
    digit_count = sum(char.isdigit() for char in label)
    consonant_clusters = re.search(r"[bcdfghjklmnpqrstvwxyz]{5,}", label.lower())
    return vowel_count <= 2 or digit_count >= 4 or bool(consonant_clusters)


def _has_brand_impersonation(host: str) -> bool:
    """Return True when the host suggests brand impersonation."""
    for brand, official_suffixes in BRAND_KEYWORDS.items():
        if brand in host and not any(host.endswith(suffix) for suffix in official_suffixes):
            return True
    return False


def derive_threat_context(ioc: str, ioc_type: str) -> list[str]:
    """Return informational threat context labels without ATT&CK attribution."""
    host = _extract_host(ioc, ioc_type)
    combined = ioc.lower()
    contexts: list[str] = []

    if any(keyword in combined for keyword in {"login", "signin", "verify", "auth", "credential"}):
        contexts.append("credential_theft_lure")

    if any(keyword in combined for keyword in CRYPTO_KEYWORDS | {"airdrop", "bonus"}):
        contexts.append("crypto_scam")

    if ioc_type in {"Domain", "URL", "Email"}:
        tld = host.split(".")[-1] if "." in host else ""
        if tld in SUSPICIOUS_TLDS or _looks_random_domain(host):
            contexts.append("suspicious_domain")
        if _has_brand_impersonation(host):
            contexts.append("brand_impersonation")

    if any(keyword in combined for keyword in {"invoice", "payment", "office365", "microsoft365"}):
        contexts.append("phishing_lure")

    deduplicated: list[str] = []
    for context in contexts:
        if context not in deduplicated:
            deduplicated.append(context)
    return deduplicated
