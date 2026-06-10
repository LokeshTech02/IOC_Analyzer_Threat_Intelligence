"""Enrichment tests for threat context, VirusTotal, and AbuseIPDB integrations."""

from __future__ import annotations

from datetime import datetime
import json

import main
from analyzer.abuseipdb import get_abuseipdb_reputation
from analyzer.threat_context import derive_threat_context
from analyzer.virustotal import (
    build_detection_ratio,
    build_finding_summary,
    calculate_malware_confidence,
    get_vt_reputation,
    test_vt_connection as vt_connection_check,
)


class MockResponse:
    """Simple context-managed HTTP response stub for API tests."""

    def __init__(self, payload: dict[str, object]) -> None:
        self.payload = payload

    def read(self) -> bytes:
        return json.dumps(self.payload).encode("utf-8")

    def __enter__(self) -> "MockResponse":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        return None


def test_threat_context_credential_theft_lure() -> None:
    context = derive_threat_context("https://example.com/login", "URL")
    assert "credential_theft_lure" in context


def test_threat_context_crypto_scam() -> None:
    context = derive_threat_context("wallet-airdrop-bonus.top", "Domain")
    assert "crypto_scam" in context
    assert "suspicious_domain" in context


def test_virustotal_disabled_mode(monkeypatch) -> None:
    monkeypatch.delenv("VT_API_KEY", raising=False)
    assert get_vt_reputation("8.8.8.8", "IPv4") == {"vt_enabled": False}


def test_virustotal_enabled_mode(monkeypatch) -> None:
    monkeypatch.setenv("VT_API_KEY", "test-key")
    monkeypatch.setattr(
        "analyzer.virustotal.urlopen",
        lambda request, timeout=10: MockResponse(
            {
                "data": {
                    "attributes": {
                        "reputation": -10,
                        "popular_threat_label": "trojan.zenpak/graftor",
                        "last_analysis_date": 1780790400,
                        "popular_threat_classification": {
                            "popular_threat_category": [
                                {"value": "trojan"},
                                {"value": "banker"},
                                {"value": "ransomware"},
                            ],
                            "popular_threat_name": [
                                {"value": "zenpak"},
                                {"value": "graftor"},
                                {"value": "dridex"},
                            ],
                        },
                        "last_analysis_stats": {
                            "malicious": 12,
                            "suspicious": 3,
                            "harmless": 20,
                        },
                    }
                }
            }
        ),
    )
    reputation = get_vt_reputation("44d88612fea8a8f36de82e1278abb02f", "MD5")
    assert reputation["vt_enabled"] is True
    assert reputation["malicious_votes"] == 12
    assert reputation["detection_ratio"] == "12/35"
    assert reputation["popular_threat_label"] == "trojan.zenpak/graftor"
    assert reputation["threat_categories"] == ["trojan", "banker", "ransomware"]
    assert reputation["malware_families"] == ["zenpak", "graftor", "dridex"]
    assert reputation["last_analysis_date"] == "2026-06-07"


def test_abuseipdb_disabled_mode(monkeypatch) -> None:
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    assert get_abuseipdb_reputation("8.8.8.8", "IPv4") == {"enabled": False}


def test_abuseipdb_enabled_mode(monkeypatch) -> None:
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "test-key")
    monkeypatch.setattr(
        "analyzer.abuseipdb.urlopen",
        lambda request, timeout=10: MockResponse(
            {
                "data": {
                    "abuseConfidenceScore": 92,
                    "countryCode": "NL",
                    "usageType": "Data Center/Web Hosting/Transit",
                    "totalReports": 154,
                }
            }
        ),
    )
    reputation = get_abuseipdb_reputation("8.8.8.8", "IPv4")
    assert reputation["enabled"] is True
    assert reputation["abuse_confidence_score"] == 92


def test_test_vt_connection_missing(monkeypatch) -> None:
    monkeypatch.delenv("VT_API_KEY", raising=False)
    assert vt_connection_check() == "missing"


def test_detection_ratio_generation() -> None:
    assert build_detection_ratio(54, 12, 0) == "54/66"


def test_malware_confidence_calculation() -> None:
    assert calculate_malware_confidence(0) == "Low"
    assert calculate_malware_confidence(5) == "Medium"
    assert calculate_malware_confidence(14) == "High"
    assert calculate_malware_confidence(54) == "Very High"


def test_finding_summary_generation() -> None:
    summary = build_finding_summary(
        {
            "vt_enabled": True,
            "malicious_votes": 54,
            "detection_ratio": "54/66",
            "threat_categories": ["trojan", "banker", "ransomware"],
            "malware_families": ["zenpak", "graftor", "dridex"],
        },
        "SHA256",
    )
    assert "54 of 66" in summary
    assert "zenpak" in summary.lower()
    assert "ransomware" in summary.lower()


def test_scan_name_generation() -> None:
    generated = main.generate_scan_name(datetime(2026, 6, 9, 20, 15, 30))
    assert generated == "scan_20260609_201530"
