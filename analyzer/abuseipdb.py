"""AbuseIPDB enrichment helpers for IOC Analyzer."""

from __future__ import annotations

import json
import os
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

ABUSEIPDB_BASE_URL = "https://api.abuseipdb.com/api/v2/check"


def get_abuseipdb_reputation(ioc: str, ioc_type: str) -> dict[str, int | str | bool]:
    """Query AbuseIPDB for IP-based indicators when configured."""
    api_key = os.getenv("ABUSEIPDB_API_KEY")
    if not api_key:
        return {"enabled": False}

    if ioc_type not in {"IPv4", "IPv6"}:
        return {
            "enabled": True,
            "abuse_confidence_score": 0,
            "country_code": "",
            "usage_type": "",
            "total_reports": 0,
        }

    request = Request(
        f"{ABUSEIPDB_BASE_URL}?ipAddress={quote(ioc, safe='')}&maxAgeInDays=90",
        headers={
            "Accept": "application/json",
            "Key": api_key,
        },
    )

    try:
        with urlopen(request, timeout=10) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (HTTPError, URLError, TimeoutError, json.JSONDecodeError):
        return {
            "enabled": True,
            "abuse_confidence_score": 0,
            "country_code": "",
            "usage_type": "",
            "total_reports": 0,
        }

    data = payload.get("data", {})
    return {
        "enabled": True,
        "abuse_confidence_score": int(data.get("abuseConfidenceScore", 0)),
        "country_code": str(data.get("countryCode", "")),
        "usage_type": str(data.get("usageType", "")),
        "total_reports": int(data.get("totalReports", 0)),
    }
