"""VirusTotal v3 enrichment helpers for IOC Analyzer."""

from __future__ import annotations

import base64
import json
import os
from datetime import UTC, datetime
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

VT_BASE_URL = "https://www.virustotal.com/api/v3"
HASH_TYPES = {"MD5", "SHA1", "SHA256"}


def _urlsafe_b64(value: str) -> str:
    """Encode a URL IOC using VirusTotal's URL identifier format."""
    encoded = base64.urlsafe_b64encode(value.encode("utf-8")).decode("ascii")
    return encoded.rstrip("=")


def _build_endpoint(ioc: str, ioc_type: str) -> str | None:
    """Return the v3 endpoint path for a supported IOC type."""
    if ioc_type in {"IPv4", "IPv6"}:
        return f"/ip_addresses/{quote(ioc, safe='')}"
    if ioc_type == "Domain":
        return f"/domains/{quote(ioc, safe='')}"
    if ioc_type == "URL":
        return f"/urls/{_urlsafe_b64(ioc)}"
    if ioc_type in HASH_TYPES:
        return f"/files/{quote(ioc, safe='')}"
    return None


def _default_vt_response(ioc_type: str) -> dict[str, int | bool | str | list[str]]:
    """Return a normalized default VT block."""
    result: dict[str, int | bool | str | list[str]] = {
        "vt_enabled": True,
        "malicious_votes": 0,
        "suspicious_votes": 0,
        "harmless_votes": 0,
        "reputation": 0,
    }
    if ioc_type in HASH_TYPES:
        result.update(
            {
                "detection_ratio": "0/0",
                "popular_threat_label": "",
                "threat_categories": [],
                "malware_families": [],
                "last_analysis_date": "",
            }
        )
    return result


def build_detection_ratio(malicious_votes: int, harmless_votes: int, suspicious_votes: int = 0) -> str:
    """Return a vendor detection ratio string."""
    total = malicious_votes + harmless_votes + suspicious_votes
    return f"{malicious_votes}/{total}"


def calculate_malware_confidence(malicious_votes: int) -> str:
    """Map VT malicious vote counts to a malware confidence label."""
    if malicious_votes == 0:
        return "Low"
    if malicious_votes <= 9:
        return "Medium"
    if malicious_votes <= 24:
        return "High"
    return "Very High"


def build_finding_summary(vt_reputation: dict[str, int | bool | str | list[str]], ioc_type: str) -> str:
    """Generate a human-readable finding summary for hash-based VT results."""
    if ioc_type not in HASH_TYPES or not vt_reputation.get("vt_enabled"):
        return ""

    detection_ratio = str(vt_reputation.get("detection_ratio", "0/0"))
    malicious_count, total_count = detection_ratio.split("/", maxsplit=1)
    families = [str(item) for item in vt_reputation.get("malware_families", [])]
    categories = [str(item) for item in vt_reputation.get("threat_categories", [])]

    malicious_votes = int(vt_reputation.get("malicious_votes", 0))
    if malicious_votes == 0:
        summary = (
            f"VirusTotal reports no active malicious detections for this file across "
            f"{total_count} reporting vendors."
        )
    else:
        summary = (
            f"VirusTotal reports {malicious_count} of {total_count} security vendors "
            f"detecting this file as malicious."
        )

    if families and categories:
        families_text = ", ".join(families[:-1]) + (f", and {families[-1]}" if len(families) > 1 else families[0])
        categories_text = ", ".join(categories[:-1]) + (
            f", and {categories[-1]}" if len(categories) > 1 else categories[0]
        )
        return (
            f"{summary} The sample is associated with the {families_text} malware families "
            f"and is categorized as a {categories_text} threat."
        )
    if families:
        families_text = ", ".join(families[:-1]) + (f", and {families[-1]}" if len(families) > 1 else families[0])
        return f"{summary} The sample is associated with the {families_text} malware families."
    if categories:
        categories_text = ", ".join(categories[:-1]) + (
            f", and {categories[-1]}" if len(categories) > 1 else categories[0]
        )
        return f"{summary} The sample is categorized as a {categories_text} threat."
    return summary


def _format_last_analysis_date(timestamp: int | None) -> str:
    """Convert a VT timestamp to YYYY-MM-DD."""
    if not timestamp:
        return ""
    return datetime.fromtimestamp(timestamp, tz=UTC).strftime("%Y-%m-%d")


def _parse_hash_file_attributes(attributes: dict[str, object]) -> dict[str, str | list[str]]:
    """Extract advanced file intelligence from VT attributes."""
    popular_threat = attributes.get("popular_threat_classification", {})
    if not isinstance(popular_threat, dict):
        popular_threat = {}

    threat_categories = [
        str(item.get("value", ""))
        for item in popular_threat.get("popular_threat_category", [])
        if isinstance(item, dict) and item.get("value")
    ]
    malware_families = [
        str(item.get("value", ""))
        for item in popular_threat.get("popular_threat_name", [])
        if isinstance(item, dict) and item.get("value")
    ]

    popular_threat_label = str(attributes.get("popular_threat_label", ""))
    if not popular_threat_label and malware_families:
        popular_threat_label = "/".join(malware_families)

    return {
        "popular_threat_label": popular_threat_label,
        "threat_categories": threat_categories,
        "malware_families": malware_families,
        "last_analysis_date": _format_last_analysis_date(
            int(attributes.get("last_analysis_date", 0) or 0)
        ),
    }


def get_vt_reputation(ioc: str, ioc_type: str) -> dict[str, int | bool | str | list[str]]:
    """Query VirusTotal when configured and return a normalized reputation block."""
    api_key = os.getenv("VT_API_KEY")
    if not api_key:
        return {"vt_enabled": False}

    endpoint = _build_endpoint(ioc, ioc_type)
    if endpoint is None:
        return _default_vt_response(ioc_type)

    request = Request(
        f"{VT_BASE_URL}{endpoint}",
        headers={
            "accept": "application/json",
            "x-apikey": api_key,
        },
    )

    try:
        with urlopen(request, timeout=10) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (HTTPError, URLError, TimeoutError, json.JSONDecodeError):
        return _default_vt_response(ioc_type)

    attributes = payload.get("data", {}).get("attributes", {})
    stats = attributes.get("last_analysis_stats", {})
    malicious_votes = int(stats.get("malicious", 0))
    suspicious_votes = int(stats.get("suspicious", 0))
    harmless_votes = int(stats.get("harmless", 0))

    result: dict[str, int | bool | str | list[str]] = {
        "vt_enabled": True,
        "malicious_votes": malicious_votes,
        "suspicious_votes": suspicious_votes,
        "harmless_votes": harmless_votes,
        "reputation": int(attributes.get("reputation", 0)),
    }

    if ioc_type in HASH_TYPES:
        result.update(_parse_hash_file_attributes(attributes))
        result["detection_ratio"] = build_detection_ratio(
            malicious_votes,
            harmless_votes,
            suspicious_votes,
        )

    return result


def test_vt_connection() -> str:
    """Validate whether the configured VirusTotal key can reach the API."""
    api_key = os.getenv("VT_API_KEY")
    if not api_key:
        return "missing"

    request = Request(
        f"{VT_BASE_URL}/ip_addresses/8.8.8.8",
        headers={
            "accept": "application/json",
            "x-apikey": api_key,
        },
    )
    try:
        with urlopen(request, timeout=10) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (HTTPError, URLError, TimeoutError, json.JSONDecodeError):
        return "failed"

    if payload.get("data"):
        return "success"
    return "failed"
